import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import { type Sandbox, bundleForImport } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  nodeRunCommand,
  NODE_SOURCE_RE,
  freshMarker,
  nodeExportedNames,
  scanSinkLeads,
} from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Broken access control is DIFFERENTIAL, not a syntactic sink. There is no single dangerous call to
// grep like `child_process.exec`; the vuln is an INCONSISTENCY — two entrypoints reach the same
// privileged effect, but one is gated behind a WEAKER authorization check than the other. This lane
// models openclaw's GHSA-j4mm-p864-vx7f (CWE-863): `sessions.create` re-applied model/thinkingLevel
// at operator.WRITE, the exact effect `sessions.patch` gates behind operator.ADMIN.
//
// So the three parts of the lane differ from the injection lanes only in FIND and ORACLE; the PROVER
// reuses the sandbox execution primitive:
//   - FIND:   pair exported entrypoints that share an effect but name different authorization scopes.
//   - PROVE:  drive BOTH under the identical low-privilege credential and observe the asymmetry.
//   - ORACLE: fired = the weak path executed the effect while the strong path rejected the SAME
//             caller with an authorization error. "Both allowed" or "strong failed non-authz" = no fire.

// A line that makes an authorization decision — the lead surface for the sweep's density ranking.
// A lead is NOT a finding: a lone scope check is correct code. The differential (a sibling reaching
// the same effect at a lower scope) + a fired PoC is what makes it a vuln.
const GUARD_RE =
  /\b(?:require|assert|check|ensure|verify)(?:Scopes?|Roles?|Permissions?|Auth|Access|Admin)\b|\bhas(?:Scope|Role|Permission)s?\s*\(|\.(?:scopes?|roles?|permissions?)\b[^=\n]*\.includes\s*\(|\bResolve\w*RequiredScopes?\b|\brequiredScopes?\b|operator\.(?:ADMIN|WRITE|READ)|\b(?:scope|role|permission)\s*===/i;

// Known authorization tiers, so a differential can be ORDERED (which side is weaker). An unknown
// scope token gets the mid rank: direction is then decided by EXECUTION (only the genuinely-lower
// credential exposes the escalation on a hierarchical scope model), not by this guess — so a wrong
// rank costs a mislabel at worst, never a false finding (the PoC still has to fire).
const SCOPE_RANK: Record<string, number> = {
  read: 1, view: 1, viewer: 1, list: 1, readonly: 1, "operator.read": 1, guest: 1,
  write: 2, edit: 2, editor: 2, manage: 2, manager: 2, member: 2, contributor: 2, create: 2, update: 2, "operator.write": 2,
  admin: 3, administrator: 3, owner: 3, superuser: 3, super: 3, root: 3, sysadmin: 3, operator: 3, "operator.admin": 3,
};

// State-provenance transitions usually involve these lifecycle verbs and nouns.
const STATE_TRANSITION_NAME_RE =
  /^(?:bootstrap|create|open|connect|reconnect|rebind|replay|resume|restore|loopback|pair|pairing|handoff|handover|bind|adopt|revoke|rotate|migrate|claim|transfer|adopt|claim|attach|replace|swap)/i;
const STATE_TRANSITION_BODY_RE = /\b(?:session|conversation|token|identity|principal|scope|capability|capabilityId|conversationId|sessionId|binding|replay|reconnect|loopback|pair|handoff|handover|delegate|impersonat|attach|rebind|migrate|claim)/i;
const PRIVILEGED_ACTION_RE = /\b(?:admin|owner|operator\.admin|superuser|sysadmin|system)\b/i;

function hasStateTransitionHint(entry: { name: string; body: string }): boolean {
  return STATE_TRANSITION_NAME_RE.test(entry.name) || STATE_TRANSITION_BODY_RE.test(entry.body);
}

function isPrivilegedAction(entry: Entry): boolean {
  const hasAdminHint = PRIVILEGED_ACTION_RE.test(entry.name) || PRIVILEGED_ACTION_RE.test(entry.body);
  const hasGuardedScope = entry.scopes.length > 0 && entry.scopes.some((s) => scopeRank(s) >= 3);
  return hasAdminHint || hasGuardedScope;
}

function scopeRank(scope: string): number {
  return SCOPE_RANK[scope.toLowerCase()] ?? 2;
}

// Tokens that are GUARDS, control-flow keywords, or plumbing — never the privileged effect itself.
// Excluded so a shared `if (`/`level()`/`requireScope()` is not mistaken for the shared sink: every
// guarded function has an `if` and calls its scope guard, which would make every pair a false candidate.
// Guard-family verbs are dropped by PREFIX (`requireScope`, `assertAdmin`, `hasRole`); keywords and
// noisy plumbing by EXACT match (a real effect like `getUserRecord`/`resolveOrder` must survive).
const JS_KEYWORDS =
  "if|for|while|switch|catch|return|typeof|instanceof|void|delete|throw|do|else|try|finally|await|yield|case|in|of|new|super|this|const|let|var|function";
const JS_KEYWORD_SET = new Set(JS_KEYWORDS.split("|"));

// A HARNESS wrapper delegates to a passed-in callback (`params.run(...)`, `opts.callback(...)`), so its
// own body is plumbing — the real effect is whatever callback each CALLER supplies. Counting the wrapper
// name as a shared effect makes every method that uses it look like a differential (raeuberkrebs #23).
// Such a unit contributes nothing to a caller's effect set and is not followed inter-procedurally.
const HARNESS_BODY_RE = /\b(?:params|opts|options|args|ctx|arg)\.(?:run|callback|handler|next|proceed|execute|fn)\s*\(/;
const GUARD_PREFIX_RE = /^(?:require|assert|check|ensure|verify|has|can|is|authorize|authorise|guard|allow|permit|must|deny|reject)/i;
const NON_EFFECT_EXACT_RE = new RegExp(
  `^(?:${JS_KEYWORDS}|level|scope|scopes|role|roles|permission|permissions|log|warn|error|debug|info|map|filter|reduce|each|get|set|json|string|number|array|object|promise)$`,
  "i",
);

/** True if a token names a privileged EFFECT (a mutation/effect helper), not a guard or plumbing. */
function isEffectToken(token: string): boolean {
  return !GUARD_PREFIX_RE.test(token) && !NON_EFFECT_EXACT_RE.test(token);
}

export interface FnUnit {
  name: string;
  body: string;
  line: number;
}

/** Slice `{ … }` from `openIdx` (a `{`) to its matching close. Not string/comment aware — a body with
 *  an unbalanced brace inside a literal just yields a slightly-off slice, which can only cause a MISS
 *  (a mis-read scope/effect), never a false finding, because the PoC must still fire. */
export function braceSlice(source: string, openIdx: number): string | null {
  let depth = 0;
  for (let i = openIdx; i < source.length; i++) {
    const c = source[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return source.slice(openIdx, i + 1);
    }
  }
  return null;
}

/** The body brace that opens a function declared at `nameIdx`: skip the parameter list (which may
 *  itself contain `{ }` destructuring / default objects), then take the first `{` of the block. Returns
 *  null for an expression-bodied arrow (no block) — those rarely carry an auth guard. */
export function bodyAfterSignature(source: string, nameIdx: number): string | null {
  const paren = source.indexOf("(", nameIdx);
  if (paren === -1 || paren - nameIdx > 80) return null;
  let depth = 0;
  let i = paren;
  for (; i < source.length; i++) {
    const c = source[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) {
        i++;
        break;
      }
    }
  }
  const rest = source.slice(i, i + 160);
  const braceRel = rest.indexOf("{");
  if (braceRel === -1) return null;
  // Reject a `{` that sits past an expression-body arrow's first statement (a stray later block).
  if (/[;)]\s*$/.test(rest.slice(0, braceRel).replace(/=>\s*$/, ""))) return null;
  return braceSlice(source, i + braceRel);
}

/** Every named function/arrow declaration with its block body, for scope+effect scanning. */
export function functionUnits(source: string): FnUnit[] {
  const units: FnUnit[] = [];
  const declRe =
    /(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*(?::[^={]+)?=>|[A-Za-z_$][\w$]*\s*=>)/g;
  let m: RegExpExecArray | null;
  while ((m = declRe.exec(source))) {
    const name = m[1] ?? m[2];
    if (!name) continue;
    const body = bodyAfterSignature(source, m.index);
    if (body == null) continue;
    units.push({ name, body, line: source.slice(0, m.index).split("\n").length });
  }
  return units;
}

/** Authorization scopes named inside a guard in this body (lowercased). Empty = the entrypoint has no
 *  authorization check at all (rank 0 — a missing-authorization sibling is the strongest differential). */
function bodyScopes(body: string): string[] {
  const scopes = new Set<string>();
  const patterns = [
    /\.(?:scopes?|roles?|permissions?)\b[^=\n]*?\.includes\s*\(\s*['"]([\w.:-]+)['"]/gi,
    /\b(?:require|assert|check|ensure|has)(?:Scopes?|Roles?|Permissions?|Auth|Admin)?\s*\(\s*['"]([\w.:-]+)['"]/gi,
    /\bhasRole\s*\([^,)]*,\s*['"]([\w.:-]+)['"]/gi,
    /\b(?:scope|role|permission)\s*===\s*['"]([\w.:-]+)['"]/gi,
    /operator\.(ADMIN|WRITE|READ)\b/g,
    /\bRANK\.([A-Za-z_$][\w$]*)/g, // a rank-table guard: `level(ctx) < RANK.admin`
  ];
  for (const re of patterns) {
    for (const g of body.matchAll(re)) {
      const raw = g[1];
      if (raw) scopes.add(re.source.includes("operator") ? `operator.${raw.toLowerCase()}` : raw.toLowerCase());
    }
  }
  return [...scopes];
}

/** Privileged-effect tokens this body reaches: locally-called helpers + mutated properties + mutation
 *  method calls. Two entrypoints that intersect here reach the SAME effect. Guards/plumbing filtered. */
function bodyEffects(body: string): Set<string> {
  const effects = new Set<string>();
  // BARE local-helper calls only (not `.method(` — a shared `.includes()`/`.map()` from the guard or
  // plumbing is not the effect; privileged `.setX()` mutations are captured by the dedicated regex below).
  for (const g of body.matchAll(/(?<![.\w$])([a-z][A-Za-z0-9_$]*)\s*\(/g)) {
    const t = g[1];
    if (t && isEffectToken(t)) effects.add(t);
  }
  for (const g of body.matchAll(/\.([A-Za-z_$][\w$]*)\s*=(?![=>])/g)) {
    const t = g[1];
    if (t && isEffectToken(t)) effects.add(`=${t}`); // an assignment to `.prop`
  }
  for (const g of body.matchAll(/\.((?:set|update|write|save|delete|remove|insert|put|patch|create|add|persist|store|apply|mutate)[A-Za-z0-9_$]*)\s*\(/gi)) {
    const t = g[1];
    if (t) effects.add(t);
  }
  return effects;
}

/** Bare local-helper calls in a body (lowercase-initial, not `.method()`, not a keyword) — the internal
 *  hops to follow when resolving inter-procedural effect reach. */
function rawLocalCalls(body: string): string[] {
  const out: string[] = [];
  for (const g of body.matchAll(/(?<![.\w$])([a-z][A-Za-z0-9_$]*)\s*\(/g)) {
    const t = g[1];
    if (t && !JS_KEYWORD_SET.has(t)) out.push(t);
  }
  return out;
}

/**
 * The effect set a body reaches, FOLLOWING bare calls into other module-local functions up to `depth`
 * hops — so an effect a handler reaches through an internal helper chain (`handler → helper → applyX`)
 * is attributed to the handler. This is the "buried sink" capability: a shallow direct-call scan only
 * sees `helper`, and would miss that a WRITE handler and an ADMIN handler converge on the same deep
 * effect. Harness wrappers contribute nothing and are not followed (raeuberkrebs #23).
 */
function closureEffects(
  name: string,
  bodyByName: Map<string, string>,
  harness: Set<string>,
  depth: number,
  seen: Set<string>,
): Set<string> {
  const acc = new Set<string>();
  if (seen.has(name) || depth < 0) return acc;
  seen.add(name);
  const body = bodyByName.get(name);
  if (body === undefined || harness.has(name)) return acc;
  for (const e of bodyEffects(body)) if (!harness.has(e)) acc.add(e);
  if (depth > 0) {
    for (const call of rawLocalCalls(body)) {
      if (bodyByName.has(call) && call !== name && !harness.has(call)) {
        for (const e of closureEffects(call, bodyByName, harness, depth - 1, seen)) acc.add(e);
      }
    }
  }
  return acc;
}

function sameScopes(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sb = new Set(b.map((s) => s.toLowerCase()));
  return a.every((s) => sb.has(s.toLowerCase()));
}

interface Entry {
  name: string;
  body: string;
  line: number;
  scopes: string[];
  effects: Set<string>;
}

interface DiffCandidate {
  weak: Entry;
  strong: Entry;
  effect: string;
}

/** Pair exported entrypoints that share a privileged effect but enforce different authorization. The
 *  lower-ranked scope side is the presumed `weak` (escalation) path; the driver confirms the direction
 *  by execution. */
function differentialCandidates(entries: Entry[]): DiffCandidate[] {
  const out: DiffCandidate[] = [];
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      const a = entries[i];
      const b = entries[j];
      const shared = [...a.effects].filter((e) => b.effects.has(e));
      if (shared.length === 0) continue;
      if (sameScopes(a.scopes, b.scopes)) continue; // identical guard → no differential
      // Lowest-ranked scope named in a body is its authority floor; an unguarded body is rank 0
      // (weakest). The lower side is the presumed escalation path; the driver grants ONLY its scope,
      // so on a hierarchical scope model only the genuinely-lower credential exposes the asymmetry.
      const rankA = a.scopes.length ? Math.min(...a.scopes.map(scopeRank)) : 0;
      const rankB = b.scopes.length ? Math.min(...b.scopes.map(scopeRank)) : 0;
      const [weak, strong] = rankA <= rankB ? [a, b] : [b, a];
      // Prefer a named-helper/mutation effect over a bare assignment for the human-readable label.
      const effect = shared.find((e) => !e.startsWith("=")) ?? shared[0];
      out.push({ weak, strong, effect });
    }
  }
  return out;
}

/**
 * Drive both entrypoints under the identical low-privilege credential and detect the authorization
 * asymmetry. Tries several context shapes ({scopes},{roles},{auth},…) and a marker-laden payload so
 * the effect actually runs. Fired = the weak path executed while the strong path rejected the SAME
 * caller with an AUTHORIZATION error (a non-authz throw from the strong path is inconclusive, not a
 * fire — that guards against a payload-shape mismatch masquerading as a denial).
 */
function bacDiffDriver(
  moduleRel: string,
  weakName: string,
  weakScopes: string[],
  strongName: string,
  marker: string,
): string {
  const mod = JSON.stringify("./" + moduleRel);
  const W = JSON.stringify(weakName);
  const S = JSON.stringify(strongName);
  const WS = JSON.stringify(weakScopes);
  const MK = JSON.stringify(marker);
  return `
const MARKER = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(name){
  if (m && typeof m[name] === "function") return m[name];
  if (m && m.default && typeof m.default[name] === "function") return m.default[name];
  return null;
}
const weak = pick(${W}), strong = pick(${S});
if (!weak || !strong) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
const PAY = { model: MARKER, value: MARKER, setting: MARKER, name: MARKER, label: MARKER, level: MARKER, thinkingLevel: MARKER, config: MARKER, data: MARKER, key: MARKER, id: MARKER };
function ctxShapes(scopes){
  const s = Array.isArray(scopes) ? scopes : (scopes ? [scopes] : []);
  const one = s[0];
  return [ { scopes: s }, { scope: one }, { roles: s }, { role: one }, { permissions: s }, { auth: { scopes: s } }, { user: { scopes: s, roles: s } }, { operator: { scopes: s } }, { session: { scopes: s } }, {} ];
}
function isAuthzErr(e){
  const t = String((e && ((e.name || "") + " " + (e.message || ""))) || e || "").toLowerCase();
  return /(authz|unauthor|forbidden|denied|permission|scope|not allowed|access|admin|require|403)/.test(t);
}
async function call(fn, ctx){
  const attempts = [[ctx, PAY], [PAY, ctx], [ctx], [PAY]];
  let ran = false, sawAuthz = false, ret;
  for (const args of attempts){
    try { ret = await fn(...args); ran = true; break; }
    catch (e){ if (isAuthzErr(e)) sawAuthz = true; }
  }
  return { ran, sawAuthz, ret };
}
function landed(ret){ try { return JSON.stringify(ret).indexOf(MARKER) !== -1; } catch { return false; } }
for (const ctx of ctxShapes(${WS})){
  const rw = await call(weak, ctx);
  if (!rw.ran) continue;            // weak path did not execute the effect under this credential shape
  const rs = await call(strong, ctx);
  if (rs.ran) continue;             // strong path ALSO allowed the same credential → equal authority, no escalation
  if (!rs.sawAuthz) continue;       // strong path failed for a non-authz reason → inconclusive, not a denial
  const land = landed(rw.ret) ? " effectMarker=1" : "";
  process.stdout.write("BAC_FIRED weak=" + ${W} + " strong=" + ${S} + " grant=" + JSON.stringify(${WS}) + land);
  process.exit(0);
}
process.stdout.write("no-bac");
`.trim();
}

function bacStatefulDriver(
  moduleRel: string,
  actionName: string,
  transitionName: string,
  marker: string,
): string {
  const mod = JSON.stringify("./" + moduleRel);
  const A = JSON.stringify(actionName);
  const T = JSON.stringify(transitionName);
  const MK = JSON.stringify(marker);

  return `
const MARKER = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("BAC_STATEFUL_IMPORT_FAIL:" + e); process.exit(0); }

function pick(n){
  if (m && typeof m[n] === "function") return m[n];
  if (m && m.default && typeof m.default[n] === "function") return m.default[n];
  return null;
}
const action = pick(${A});
const transition = pick(${T});
if (!action || !transition) { process.stdout.write("BAC_STATEFUL_NOT_A_FUNCTION"); process.exit(0); }

function asText(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v); } catch { return String(v); }
}
function hasMarker(v) {
  return asText(v).indexOf(MARKER) !== -1;
}
function isAuthzErr(e) {
  const t = String((e && ((e.name || "") + " " + (e.message || ""))) || e || "").toLowerCase();
  return /(forbidden|denied|access|permission|not allowed|not authorized|unauthorized|scope|admin|owner|token|session|principal|identity|scope)/.test(t);
}
async function call(fn, attempts) {
  let authzErr = false;
  let lastErr = null;
  for (const args of attempts) {
    try {
      return { ok: true, ret: await fn(...args) };
    } catch (e) {
      lastErr = e;
      if (isAuthzErr(e)) authzErr = true;
    }
  }
  return { ok: false, ret: lastErr, authzErr };
}
function collectIds(v, out) {
  if (out === undefined) out = [];
  if (v == null) return out;
  if (typeof v === "string" && v.length < 120) {
    out.push(v);
    return out;
  }
  if (Array.isArray(v)) {
    for (const x of v) collectIds(x, out);
    return out;
  }
  if (typeof v === "object") {
    for (const k of [
      "sessionId",
      "conversationId",
      "capabilityId",
      "token",
      "principal",
      "principalId",
      "identity",
      "identityId",
      "actor",
      "actorId",
      "scope",
      "scopeId",
      "capability",
      "session",
      "attackerSessionId",
      "ownerSessionId",
      "fromSessionId",
      "toSessionId",
      "fromSession",
      "toSession",
      "sessionFromId",
      "sessionToId",
      "targetSessionId",
    ]) {
      if (v && typeof (v[k]) === "string") collectIds(v[k], out);
    }
  }
  return out;
}
function uniqueStrings(list) {
  return [...new Set(list.filter((x) => typeof x === "string" && x.length <= 120))];
}
function asIdList(v) {
  return uniqueStrings(collectIds(v, []));
}
function withSessionHints(payload, sessionId) {
  if (!payload || typeof payload !== "object" || sessionId == null) return payload;
  return Object.assign({}, payload, {
    sessionId: payload.sessionId || sessionId,
    conversationId: payload.conversationId || sessionId,
    conversation: payload.conversation || sessionId,
    token: payload.token || sessionId,
    session: payload.session || sessionId,
  });
}
function transitionPayloadCandidates(basePatch, ids) {
  const patch = Object.assign({}, basePatch);
  if (!ids || ids.length === 0) return [patch];
  const first = ids[0];
  const second = ids[1] || ids[0];
  const primary = Object.assign({}, patch);
  if (primary.fromSessionId == null && primary.fromSession == null) {
    primary.fromSessionId = first;
    primary.fromSession = first;
  }
  if (primary.toSessionId == null && primary.toSession == null) {
    primary.toSessionId = second;
    primary.toSession = second;
  }
  const reversed = Object.assign({}, patch);
  if (reversed.fromSessionId == null && reversed.fromSession == null) {
    reversed.fromSessionId = second;
    reversed.fromSession = second;
  }
  if (reversed.toSessionId == null && reversed.toSession == null) {
    reversed.toSessionId = first;
    reversed.toSession = first;
  }
  return [patch, primary, reversed];
}

function snapshot() {
  const names = ["snapshotState", "snapshot", "dumpState", "sessionState", "capabilityState", "provenanceState"];
  for (const name of names) {
    try {
      if (typeof m[name] === "function") return asText(m[name]());
      if (m[name] !== undefined) return asText(m[name]);
    } catch {}
  }
  return "<unavailable>";
}
function contextShapes() {
  return [
    { identity: "attacker-" + MARKER, identityId: "attacker-" + MARKER, scopes: ["write"], principal: "attacker-" + MARKER },
    { identity: "writer-" + MARKER, roles: ["writer"], scopes: ["writer"] },
    { identity: "viewer-" + MARKER, role: "writer", scopes: ["writer"] },
    { identity: "operator-" + MARKER, operator: { scopes: ["write"] } },
    { user: { identity: "attacker-" + MARKER, scopes: ["write"] } },
    {},
  ];
}

const ACTION_PAYLOADS = [
  { marker: MARKER, action: MARKER, data: MARKER, command: MARKER, token: "tok-" + MARKER, sessionId: "sess-" + MARKER, conversationId: "conv-" + MARKER, principal: "attacker-" + MARKER },
  { marker: MARKER, action: MARKER, data: MARKER, command: MARKER, tool: "admin", token: "owner-token-" + MARKER, scope: "admin", principal: "owner-" + MARKER },
  { marker: MARKER, payload: { marker: MARKER, token: "tok-" + MARKER, action: MARKER } },
];

const TRANSITION_PAYLOADS = [
  { marker: MARKER, replay: "owner", fromSessionId: "sess-owner-" + MARKER, toSessionId: "sess-" + MARKER, principalId: "attacker-" + MARKER, principal: "attacker-" + MARKER, capabilityId: "cap-" + MARKER, scope: "admin" },
  { marker: MARKER, reconnect: "owner", fromSessionId: "sess-owner-" + MARKER, toSessionId: "sess-" + MARKER, identityId: "attacker-" + MARKER, token: "tok-" + MARKER, principal: "attacker-" + MARKER },
  { marker: MARKER, loopback: "rebind", fromSession: "sess-owner-" + MARKER, toSession: "sess-" + MARKER, principalId: "attacker-" + MARKER },
];

const bootstrapConversation = pick("bootstrapConversation");
const baseScope = "write";
let anyFired = false;
for (const ctx of contextShapes()) {
  const bootstrapResult = bootstrapConversation !== null && transition !== bootstrapConversation
    ? await call(bootstrapConversation, [[ctx], [ctx, "attacker-" + MARKER], [{}]])
    : { ok: false, ret: null, authzErr: false };
  const bootstrapIds = asIdList(bootstrapResult.ok ? bootstrapResult.ret : []);
  const baselineSessionIds = bootstrapIds.length ? bootstrapIds : ["sess-" + MARKER, "sess-owner-" + MARKER, "o" + MARKER];

  let baselineBlocked = false;
  for (const payload of ACTION_PAYLOADS) {
    let sawAttempt = false;
    for (const sid of baselineSessionIds) {
      const request = withSessionHints(payload, sid);
      const before = await call(action, [
        [ctx, sid, request],
        [ctx, sid],
        [ctx, request],
        [ctx, request, sid],
        [ctx],
        [sid, request],
        [request, sid],
        [request],
        [sid],
      ]);
      if (before.ok && hasMarker(before.ret)) {
        process.stdout.write("no-bac-stateful");
        process.exit(0);
      }
      if (before.ok || before.authzErr) baselineBlocked = true;
      sawAttempt = true;
    }
    if (!sawAttempt) baselineBlocked = true;
  }
  if (!baselineBlocked) continue;

  const beforeSnap = snapshot();
  for (const patch of TRANSITION_PAYLOADS) {
    for (const mutation of transitionPayloadCandidates(patch, baselineSessionIds)) {
      const mut = await call(transition, [
        [ctx, mutation],
        [mutation, ctx],
        [ctx],
        [mutation],
        [ctx, mutation, mutation],
        [mutation, mutation],
      ]);
      if (!mut.ok) continue;
      const transitionTrace = asText(mut.ret).slice(0, 260);
      const transitionIds = uniqueStrings(collectIds(mutation, []).concat(collectIds(mut.ret, [])));
      const actionCandidates = transitionIds.length ? transitionIds : baselineSessionIds;
      for (const id of actionCandidates) {
        for (const payload of ACTION_PAYLOADS) {
          const withId = withSessionHints(payload, id);
          withId.capabilityId = withId.capabilityId || id;
          const before = await call(action, [
            [ctx, id, withId],
            [ctx, id],
            [ctx, withId],
            [ctx, withId, id],
            [withId],
            [id, withId],
            [withId, id],
            [withId, id, withId],
            [id],
          ]);
          if (!before.ok || !hasMarker(before.ret)) continue;
          const principalId = (ctx && (ctx.identity || ctx.principal || (ctx.user && ctx.user.identity) || ctx.userId || "attacker-" + MARKER));
          const finalSnap = snapshot();
          const beforeIds = uniqueStrings(collectIds(beforeSnap, [])).filter((x) => x.length > 0);
          const afterIds = uniqueStrings(collectIds(finalSnap, []));
          const transitionEvidenceIds = uniqueStrings(collectIds(mut.ret, []));
          const principalEvidenceIds = uniqueStrings([
            principalId,
            ...collectIds(transition, []),
            ...collectIds(mut.ret || {}, []),
            ...collectIds(before.ret || {}, []),
          ]);
          const evidence = {
            action: ${A},
            transition: ${T},
            principal: principalId,
            baselineScope: baseScope,
            transitionResult: transitionTrace,
            transitionIds: transitionIds,
            preTransitionStateIds: beforeIds,
            postTransitionStateIds: afterIds,
            transitionEvidenceIds,
            principalIds: principalEvidenceIds,
            scopeTrace: [
              { step: "before-action", ids: beforeIds },
              { step: "after-transition", ids: afterIds },
              { step: "after-exploit", ids: transitionEvidenceIds },
            ],
            before: beforeSnap.slice(0, 420),
            after: finalSnap.slice(0, 420),
          };
          process.stdout.write("BAC_STATEFUL_FIRED " + JSON.stringify(evidence));
          anyFired = true;
          process.exit(0);
        }
      }
    }
    if (anyFired) break;
  }
  if (anyFired) break;
}
if (!anyFired) process.stdout.write("no-bac-stateful");
`.trim();
}

export class BrokenAccessControlAttacker implements Attacker {
  readonly attackClass = "broken-access-control" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "broken-access-control-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    // The lead surface is authorization-decision lines: the sweep ranks files by how much authz logic
    // they carry, pointing the differential hunt at the scope-declaration hotspots (openclaw's gateway
    // method-scope files rank high). Unproven by construction — the differential + PoC is the finding.
    return scanSinkLeads(source, GUARD_RE);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    for (const file of files) {
      if (!this.handles(file)) continue;
      let source: string;
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!GUARD_RE.test(source)) continue; // no authorization logic → no differential to prove here
      const exported = new Set(nodeExportedNames(source));
      if (exported.size < 2) continue; // a differential needs two drivable entrypoints
      const units = functionUnits(source);
      const bodyByName = new Map(units.map((u) => [u.name, u.body]));
      const harness = new Set(units.filter((u) => HARNESS_BODY_RE.test(u.body)).map((u) => u.name));
      const allEntries: Entry[] = units
        .filter((u) => exported.has(u.name))
        .map((u) => ({
          name: u.name,
          body: u.body,
          line: u.line,
          scopes: bodyScopes(u.body),
          // Inter-procedural: reach effects buried behind up to 3 hops of internal helpers.
          effects: closureEffects(u.name, bodyByName, harness, 3, new Set()),
        }));
      const entries: Entry[] = allEntries.filter((e) => e.effects.size > 0);
      if (entries.length === 0 && allEntries.length === 0) {
        continue;
      }

      const candidates = differentialCandidates(entries).slice(0, 8); // cost-control cap
      for (const cand of candidates) {
        const marker = freshMarker();
        const driverRel = `.raeuber-bac-${marker}.mjs`;
        sandbox.writeFile(driverRel, bacDiffDriver(bundleForImport(sandbox, file) ?? file, cand.weak.name, cand.weak.scopes, cand.strong.name, marker));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        if (!out.includes("BAC_FIRED")) continue;
        const weakScope = cand.weak.scopes.length ? cand.weak.scopes.join("+") : "(no authorization check)";
        const strongScope = cand.strong.scopes.length ? cand.strong.scopes.join("+") : "(unknown)";
        exploits.push({
          attackClass: "broken-access-control",
          proof: "privilege-escalated",
          file,
          line: cand.weak.line,
          sink: `authz-differential(${cand.effect})`,
          summary:
            `Exported \`${cand.weak.name}()\` reaches the effect \`${cand.effect}\` gated only by \`${weakScope}\`, while sibling \`${cand.strong.name}()\` gates the SAME effect behind \`${strongScope}\`. A caller with the weaker credential escalates to the more-privileged sibling's effect (CWE-863).`,
          payload: `${cand.weak.name}({ scopes: ${JSON.stringify(cand.weak.scopes)} }, { <effect fields>: "${marker}" })`,
          evidence:
            `driver drove BOTH entrypoints under the identical \`${weakScope}\` credential: \`${cand.weak.name}()\` ran the ` +
            `\`${cand.effect}\` effect, while \`${cand.strong.name}()\` REJECTED the same caller with an authorization error.\n` +
            out.slice(0, 700),
        });
        break; // one proven differential per file is enough to fail the gate
      }

      if (exploits.length > 0) {
        continue;
      }

      const statefulActions = allEntries
        .filter((e) => isPrivilegedAction(e) && !HARNESS_BODY_RE.test(e.body))
        .slice(0, 4);
      const statefulTransitions = allEntries.filter((e) => hasStateTransitionHint(e) && !HARNESS_BODY_RE.test(e.body)).slice(0, 4);
      if (statefulActions.length === 0 || statefulTransitions.length === 0) {
        continue;
      }
      for (const action of statefulActions) {
        if (exploits.length > 0) break;
        for (const transition of statefulTransitions) {
          if (exploits.length > 0) break;
          if (action.name === transition.name) continue;
          const marker = freshMarker();
          const driverRel = `.raeuber-bac-state-${marker}.mjs`;
          sandbox.writeFile(driverRel, bacStatefulDriver(bundleForImport(sandbox, file) ?? file, action.name, transition.name, marker));
          const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          if (!out.includes("BAC_STATEFUL_FIRED")) continue;
          const baselineScope = action.scopes.length ? action.scopes.join("+") : "(no authorization check)";
          exploits.push({
            attackClass: "broken-access-control",
            proof: "privilege-escalated",
            file,
            line: action.line,
            sink: `stateful-access-control(${action.name} via ${transition.name})`,
            summary:
              `Exported control-plane transition function \`${transition.name}()\` can rewrite capability provenance for \`${action.name}()\` ` +
              `from \`${baselineScope}\` to an effective higher scope, allowing lower-privilege callers to execute a privileged action after reconnect/replay-style transitions.`,
            payload: `${transition.name}({ sessionId: "sess-${marker}", action: "${marker}" }) → ${action.name}({ ... }, { marker: "${marker}" })`,
            evidence: out.slice(0, 900),
          });
          break;
        }
      }
    }
    return exploits;
  }
}

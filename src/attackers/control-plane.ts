import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  NODE_RUN,
  NODE_SOURCE_RE,
  freshMarker,
  nodeExportedNames,
  scanSinkLeads,
} from "./attacker.js";
import { functionUnits } from "./broken-access-control.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Control-plane differential lane (CWE-640/CWE-693 class): one exported control-plane entrypoint
// (`set*`, `patch*`, `update*` of policy/config) can mutate runtime safeguards, and another
// exported entrypoint still reaches protected behavior without the original boundary. The differential is
// stateful and proven in sandbox: baseline protected action is rejected, config mutation is accepted
// under weaker context, and the same action then executes a marker.
const CONTROL_PLANE_SURFACE_RE =
  /\b(?:approval|approve|allow(?:list)?|endpoint|endpoint[s]?(?:Root|s)?|tool(?:chain)?|permission|policy|setting[s]?|config|environment|env|control\s*plane)\b/i;

// Candidate mutator functions that change policy state.
const MUTATOR_NAME_RE =
  /^(?:set|patch|update|configure|reconfigure|toggle|enable|disable|allow|allowlist|approval|policy|config|policy|endpoint|environment|env|tools?)/i;

// Candidate protected-action functions that should be gated by those policy controls.
const ACTION_NAME_RE =
  /^(?:run|execute|invoke|dispatch|request|fetch|call|send|process|perform|apply|handle|probe|action|operate|open|read|write|create|delete|persist|delete)/i;

function hasControlStateShape(body: string): boolean {
  return /\b(config|policy|settings?|approval|allow(?:list)?|endpoint|tool|environment|env|boundary)\b/i.test(body);
}

interface Entry {
  name: string;
  line: number;
  body: string;
  mutatesControl: boolean;
  touchesActionBoundary: boolean;
}

/**
 * Drive a control-plane mutation then a gated action.
 * 1) capture policy snapshot
 * 2) baseline the candidate action as a low-privilege caller (expect boundary hit)
 * 3) mutate config/policy as low-privilege caller
 * 4) re-run same action under same caller; if marker lands, policy boundary became attacker-controlled.
 */
function controlPlaneDriver(moduleRel: string, mutatorName: string, actionName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const M = JSON.stringify(mutatorName);
  const A = JSON.stringify(actionName);
  const MK = JSON.stringify(marker);

  return `
const MARKER = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){
  if (m && typeof m[n] === "function") return m[n];
  if (m && m.default && typeof m.default[n] === "function") return m.default[n];
  return null;
}
const mut = pick(${M}), act = pick(${A});
if (!mut || !act) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }

function asText(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v); } catch { return String(v); }
}
function hasMarker(v) {
  return asText(v).indexOf(MARKER) !== -1;
}
function isControlErr(e) {
  const t = String((e && ((e.name || "") + " " + (e.message || ""))) || e || "").toLowerCase();
  return /(approval|allow|denied|forbidden|permission|not allowed|blocked|boundary|required|not authorized|unauthorized|invalid|policy|tool|endpoint|environment|env)/.test(t);
}
async function call(fn, attempts) {
  let authzErr = false;
  let lastErr = null;
  for (const args of attempts){
    try { const ret = await fn(...args); return { ok: true, ret }; }
    catch (e) { lastErr = e; if (isControlErr(e)) authzErr = true; }
  }
  return { ok: false, authzErr, lastErr };
}
function snapshot(){
  const snapNames = ["snapshotConfig", "snapshot", "dumpConfig", "getConfig", "getPolicy", "getSettings", "policySnapshot", "configSnapshot"];
  for (const n of snapNames){
    try {
      if (typeof m[n] === "function") return asText(m[n]());
      const v = m[n];
      if (v && typeof v === "object") return asText(v);
    } catch {}
  }
  return "<unavailable>";
}
function contexts() {
  return [
    { scopes: ["write"] }, { scopes: ["editor"] }, { role: "writer" }, { roles: ["writer"] },
    { user: { scopes: ["write"] } }, { identity: "writer-" + MARKER }, {}
  ];
}
const ACTION_PAYLOADS = [
  { marker: MARKER, action: MARKER, command: MARKER, data: MARKER, endpoint: "https://edge.example/allowed", tool: "shell", approved: true, value: MARKER },
  { marker: MARKER, action: MARKER, command: MARKER, tool: "shell", approved: false, endpoint: "https://evil.example/attack", value: MARKER },
  { marker: MARKER, action: MARKER, payload: { action: MARKER, marker: MARKER }, tool: "shell", approved: MARKER },
];
const MUTATOR_PAYLOADS = [
  { approvalMode: "off" },
  { approvalRequired: false },
  { allowlist: ["*"], allowedTools: ["*"], endpointRoots: ["https://"], inheritEnv: true },
  { tools: { exec: true, shell: true, run: true }, policyMode: "open", allowAll: true },
];

async function actionAttempts(payload, ctx) {
  return [
    [ctx, payload],
    [{}, payload],
    [ctx, {}],
    [ctx],
    [payload, payload],
    [payload],
    [{}],
  ];
}
function mutatorAttempts(payload, ctx) {
  return [
    [ctx, payload],
    [payload, ctx],
    [payload],
    [ctx],
  ];
}

let fired = false;
const before = snapshot();
for (const ctx of contexts()) {
  let blocked = false;
  for (const payload of ACTION_PAYLOADS) {
    const baseline = await call(act, await actionAttempts(payload, ctx));
    if (baseline.ok && hasMarker(baseline.ret)) { process.stdout.write("no-control-plane"); process.exit(0); }
    if (baseline.authzErr) blocked = true;
  }
  if (!blocked) continue;
  for (const patch of MUTATOR_PAYLOADS) {
    const mutRes = await call(mut, mutatorAttempts(patch, ctx));
    if (!mutRes.ok) continue;
    const after = snapshot();
    for (const payload of ACTION_PAYLOADS) {
      const r = await call(act, await actionAttempts(payload, ctx));
      if (!r.ok || !hasMarker(r.ret)) continue;
      process.stdout.write(
        "CONTROL_PLANE_FIRED mutator=" + ${M} +
          " action=" + ${A} +
          " before=" + before.slice(0, 300) +
          " after=" + after.slice(0, 300)
      );
      fired = true;
      process.exit(0);
    }
  }
}
if (!fired) process.stdout.write("no-control-plane");
`.trim();
}

export class ControlPlaneAttacker implements Attacker {
  readonly attackClass = "control-plane" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "control-plane-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    // Leads are where control-plane surfaces are visible; the PoC must prove a protected action
    // became enabled after a low-privilege config mutation.
    return scanSinkLeads(source, CONTROL_PLANE_SURFACE_RE);
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
      const exported = new Set(nodeExportedNames(source));
      const entries: Entry[] = functionUnits(source)
        .filter((u) => exported.has(u.name))
        .map((u) => ({
          name: u.name,
          line: u.line,
          body: u.body,
          mutatesControl:
            MUTATOR_NAME_RE.test(u.name) || (hasControlStateShape(u.body) && /Object\.assign|=\s*/.test(u.body)),
          touchesActionBoundary: ACTION_NAME_RE.test(u.name) && hasControlStateShape(u.body),
        }));

      const mutators = entries.filter((e) => e.mutatesControl).slice(0, 6);
      const actions = entries.filter((e) => e.touchesActionBoundary).slice(0, 8);
      if (mutators.length === 0 || actions.length === 0) continue;

      let fired = false;
      for (const mutator of mutators) {
        if (fired) break;
        for (const action of actions) {
          if (mutator.name === action.name) continue;
          const token = freshMarker();
          const driverRel = `.raeuber-control-plane-${token}.mjs`;
          sandbox.writeFile(driverRel, controlPlaneDriver(file, mutator.name, action.name, token));
          const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          if (!out.includes("CONTROL_PLANE_FIRED")) continue;
          exploits.push({
            attackClass: "control-plane",
            proof: "privilege-escalated",
            file,
            line: action.line,
            sink: `control-plane(${mutator.name}→${action.name})`,
            summary:
              `Exported control-plane mutator \`${mutator.name}()\` can rewrite runtime policy/config as a ` +
              `weaker caller, and the protected action \`${action.name}()\` then executes a marker payload that was previously blocked by control-plane checks. ` +
              `This is stateful control-plane integrity loss: configuration changes are used to disable original boundaries (CWE-640 / CWE-693 style).`,
            payload: `${mutator.name}({ scopes: ["write"] }, { approvalMode: "off" }) → ${action.name}({ action: "${token}" ... })`,
            evidence: out.slice(0, 700),
          });
          fired = true;
          break;
        }
      }
    }
    return exploits;
  }
}

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import {
  type Attacker,
  type StaticLead,
  nodeRunCommand,
  NODE_SOURCE_RE,
  freshMarker,
  nodeExportedNames,
} from "./attacker.js";
import { functionUnits } from "./broken-access-control.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const LAUNCHER_NAME_RE = /^(?:run|exec|spawn|dispatch|invoke|handle|launch|command|execute)/i;
const POLICY_RE = /\b(?:approval|allow(?:list)?|authorization|authorize|policy|approve|denied|forbidden|blocked|permission|not allowed|requires?)\b/i;
const LAUNCH_RE = /\b(?:exec(?:Sync|FileSync)?|spawn(?:Sync)?|child_process)\b/i;
const CALLEE_RE = /(?<![.\w$])([a-z][A-Za-z0-9_$]*)\s*\(/g;

type CmdArgv = string[];

interface FunctionEntry {
  name: string;
  line: number;
  body: string;
}

function transitiveLauncherCall(
  name: string,
  bodyByName: Map<string, string>,
  seen: Set<string>,
  depth = 2,
): boolean {
  if (depth < 0) return false;
  if (seen.has(name)) return false;
  seen.add(name);

  const body = bodyByName.get(name);
  if (!body) return false;
  if (LAUNCH_RE.test(body)) return true;

  for (const m of body.matchAll(CALLEE_RE)) {
    const callee = m[1];
    if (!callee || !bodyByName.has(callee)) continue;
    if (transitiveLauncherCall(callee, bodyByName, seen, depth - 1)) return true;
  }
  return false;
}

function transitivePolicyCheck(
  name: string,
  bodyByName: Map<string, string>,
  seen: Set<string>,
  depth = 2,
): boolean {
  if (depth < 0) return false;
  if (seen.has(name)) return false;
  seen.add(name);

  const body = bodyByName.get(name);
  if (!body) return false;
  if (POLICY_RE.test(body)) return true;

  for (const m of body.matchAll(CALLEE_RE)) {
    const callee = m[1];
    if (!callee || !bodyByName.has(callee)) continue;
    if (transitivePolicyCheck(callee, bodyByName, seen, depth - 1)) return true;
  }
  return false;
}

function functionCandidates(source: string): FunctionEntry[] {
  const bodyByName = new Map(functionUnits(source).map((u) => [u.name, u.body]));
  const exported = new Set(nodeExportedNames(source));
  return functionUnits(source)
    .filter((u) => exported.has(u.name))
    .filter((u) => LAUNCHER_NAME_RE.test(u.name))
    .filter((u) => POLICY_RE.test(u.body) || transitivePolicyCheck(u.name, bodyByName, new Set(), 2))
    .filter((u) => LAUNCH_RE.test(u.body) || transitiveLauncherCall(u.name, bodyByName, new Set(), 2))
    .map((u) => ({ name: u.name, line: u.line, body: u.body }));
}

function asNodeEvalPayload(marker: string): string {
  return `console.log(${JSON.stringify(marker)});`;
}

function asShellPayload(marker: string): string {
  return `echo ${marker}`;
}

function differentialCases(marker: string): Array<{ id: string; canonical: CmdArgv; approved: CmdArgv }> {
  const markerEval = asNodeEvalPayload(marker);
  const markerShell = asShellPayload(marker);

  return [
    {
      id: "node-eval-alias",
      canonical: ["node", "--eval", markerEval],
      approved: ["node", "-e", markerEval],
    },
    {
      id: "posix-flags-combined",
      canonical: ["sh", "-l", "-c", markerShell],
      approved: ["sh", "-lc", markerShell],
    },
    {
      id: "inline-flags",
      canonical: ["sh", "-e", "-c", markerShell],
      approved: ["sh", "-ec", markerShell],
    },
    {
      id: "wrapper-chain",
      canonical: ["sh", "-c", markerShell],
      approved: ["env", "-i", "sh", "-c", markerShell],
    },
  ];
}

function execAuthorizationDriver(moduleRel: string, launcherName: string, marker: string): string {
  const mod = JSON.stringify(`./${moduleRel}`);
  const fn = JSON.stringify(launcherName);
  const MK = JSON.stringify(marker);
  const CASES = JSON.stringify(differentialCases(marker));

  return `
const MARKER = ${MK};
const CASES = ${CASES};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }

function pick(name) {
  if (m && typeof m[name] === "function") return m[name];
  if (m && m.default && typeof m.default[name] === "function") return m.default[name];
  return null;
}

const launcher = pick(${fn});
if (!launcher) {
  process.stdout.write("NOT_A_FUNCTION");
  process.exit(0);
}

function asText(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v); } catch { return String(v); }
}

function isAuthzErr(e) {
  const t = String((e && ((e.name || "") + " " + (e.message || e || ""))) || "").toLowerCase();
  return /(approval|allow|denied|forbidden|blocked|permission|not allowed|not authorized|unauthorized|policy|require|approve|required)/.test(t);
}

function authzErrorText(e) {
  const name = e && e.name ? String(e.name) : "";
  const msg = e && e.message ? String(e.message) : "";
  const fallback = e ? String(e) : "";
  return [name, msg].filter(Boolean).join(" ") || fallback;
}

function hasMarker(v) {
  return asText(v).includes(MARKER);
}

async function callLauncher(payload) {
  const attempts = [
    [payload],
    [payload, {}],
    [{}, payload],
    [payload, null],
    [null, payload],
    ["", payload],
  ];

  let blocked = false;
  let output = "";

  for (const args of attempts) {
    try {
      const out = await Promise.resolve(launcher(...args));
      output = asText(out);
      if (hasMarker(output)) return { fired: true, blocked: false, output };
    } catch (e) {
      output = asText(e);
      if (isAuthzErr(authzErrorText(e))) blocked = true;
      if (hasMarker(output)) return { fired: true, blocked: true, output };
    }
  }

  return { fired: false, blocked, output };
}

for (const c of CASES) {
  const base = await callLauncher(c.canonical);
  const bypass = await callLauncher(c.approved);
  if (!bypass.fired || !base.blocked) continue;
  process.stdout.write(
    "AUTHZ_DIFF_FIRED " +
      JSON.stringify({
        id: c.id,
        launcher: ${fn},
        canonical: c.canonical,
        approved: c.approved,
      })
  );
  process.exit(0);
}

process.stdout.write("AUTHZ_DIFF_NO_MATCH");
`.trim();
}

export class ExecAuthorizationAttacker implements Attacker {
  readonly attackClass = "exec-authorization" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "exec-authorization-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return functionCandidates(source).map((fn) => ({ line: fn.line, sink: `exec-authorization(${fn.name})` }));
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

      const entries = functionCandidates(source);
      if (entries.length === 0) continue;

      for (const fn of entries) {
        const marker = freshMarker();
        const driver = `.raeuber-exec-authz-${marker}.mjs`;
        sandbox.writeFile(driver, execAuthorizationDriver(file, fn.name, marker));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driver} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        const m = out.match(/AUTHZ_DIFF_FIRED (\{.*\})/);
        if (!m) continue;

        let payloadData: { id?: string; canonical?: CmdArgv; approved?: CmdArgv } = {};
        try {
          payloadData = JSON.parse(m[1] ?? "{}");
        } catch {}
        if (!payloadData || !Array.isArray(payloadData.canonical) || !Array.isArray(payloadData.approved)) continue;

        exploits.push({
          attackClass: "exec-authorization",
          proof: "marker-executed",
          file,
          line: fn.line,
          sink: `exec-authorization(${fn.name})`,
          summary:
            `Exported command launcher \`${fn.name}\`() performs semantic policy filtering for command launch, ` +
            `but a canonical-equivalent argv form (${payloadData.id ?? "form"}) still executes a marker payload.`,
          payload:
            `approvedArgv=${JSON.stringify(payloadData.approved)} canonicalPolicyArgv=${JSON.stringify(payloadData.canonical)}`,
          evidence: out.slice(0, 900),
        });
        break;
      }
    }
    return exploits;
  }
}

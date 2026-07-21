// Differential-oracle primitive for C# (.NET) targets — the compiled-language counterpart to
// src/differential-oracle.ts. The Node oracle `import()`s a module and evaluates a JS `beliefExpr`;
// C# is compiled, so this instead assembles the target source + a generated `Driver.cs` + a csproj
// into an isolated console project (exactly as the .NET command-injection lane does), `dotnet build`s
// it, and runs the belief-vs-ground-truth loop in-process. It reuses the drive-and-prove machinery in
// dotnet.ts, so a file that needs the rest of its project to compile simply won't build in isolation —
// an honest miss (no finding), never a false pass.
//
// Two oracle shapes, because a C# security control's "ground truth" is typed, not duck-typed:
//   1. command-approval  (`differentialOracleDotnet`) — the exec-approval class (openclaw's family):
//      a `bool Decision(string cmd)` gate. Belief = the gate returns true; ground truth = running the
//      command fires the benign marker. Divergence = auto-approved AND it actually ran.
//   2. authz fail-open   (`authzFailOpenDotnet`)      — the differential-authorization class (CWE-862/
//      863): a `bool IsAuthorized(ClaimsPrincipal)` gate. Belief-vs-truth here is the NULL-AUTHORITY
//      invariant — a role/permission gate MUST deny a principal that carries no roles/claims. Ground
//      truth = construct the empty principal and call the gate; fired = it returned true (admitted the
//      role-less caller). This needs no knowledge of the intended policy, and it correctly does NOT
//      fire on a sound gate (e.g. `GetUserRoles().Any(r => allowed.Contains(r))` denies the empty set).
//
// Both obey the family rule — evidence or it didn't count: a control that merely looks wrong is a
// lead; belief-safe AND the marker/admission actually happened is a finding. Each ships a planted-
// flawed C# fixture its canary must fire against, or the lane is quarantined (fail-closed).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import { DOTNET_SOURCE_RE, DOTNET_ENV, dotnetTfm, dotnetDriverCsproj, csharpNamespace } from "./dotnet.js";

/** A public method parsed with enough shape to both FILTER (return type, first-param type, name) and
 *  CALL it from a generated driver (qualified class, static/instance, sync/async). Regex-level, like
 *  csharpDrivableMethods — good enough to drive helper/utility entrypoints, honest about missing ones
 *  hidden behind dependency-injected constructors (those just won't compile in isolation → skipped). */
export interface DecisionMethod {
  name: string;
  className: string;
  namespace: string | null;
  retType: string; // sans namespace, e.g. "bool" | "Task<bool>"
  firstParamType: string; // sans namespace, e.g. "string" | "ClaimsPrincipal"
  isStatic: boolean;
  isAsync: boolean; // returns Task<…>/ValueTask<…> (await-unwrapped when called)
}

const LAST_SEGMENT = (t: string): string => t.replace(/<.*$/, "").split(".").pop() ?? t;

/** Every public method with its first parameter, resolving the enclosing type and static/async shape.
 *  Return/param types are captured without embedded spaces (so `System.Threading.Tasks.Task<bool>` is
 *  one token) and reported sans namespace for filtering. */
export function csharpDecisionMethods(source: string): DecisionMethod[] {
  const ns = csharpNamespace(source);
  const methods: DecisionMethod[] = [];
  // public [static|async|virtual|override|sealed|new]* <RetType> <Name>( [this] <ParamType> <ParamName>
  const re =
    /\bpublic\s+((?:(?:static|async|virtual|override|sealed|new)\s+)*)([\w.<>?\[\],]+)\s+([A-Za-z_]\w*)\s*\(\s*(?:this\s+)?([\w.<>?\[\],]+)\s+([A-Za-z_]\w*)/g;
  const keywords = new Set(["if", "while", "for", "foreach", "switch", "catch", "using", "lock", "return"]);
  for (const m of source.matchAll(re)) {
    const mods = m[1] ?? "";
    const retTypeRaw = m[2];
    const name = m[3];
    const firstParamTypeRaw = m[4];
    if (keywords.has(name)) continue;
    const idx = m.index ?? 0;
    const before = source.slice(0, idx);
    const classMatches = [...before.matchAll(/\b(?:class|record|struct)\s+([A-Za-z_]\w*)/g)];
    if (classMatches.length === 0) continue;
    const className = classMatches[classMatches.length - 1][1];
    const retType = LAST_SEGMENT(retTypeRaw) + (retTypeRaw.includes("<") ? retTypeRaw.slice(retTypeRaw.indexOf("<")) : "");
    const isAsync = /\basync\b/.test(mods) || /^(?:Task|ValueTask)\b/.test(retType);
    methods.push({
      name,
      className,
      namespace: ns,
      retType,
      firstParamType: LAST_SEGMENT(firstParamTypeRaw),
      isStatic: /\bstatic\b/.test(mods),
      isAsync,
    });
  }
  // De-dup by type+name (drive an overload set once).
  const seen = new Set<string>();
  return methods.filter((x) => {
    const k = `${x.className}.${x.name}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Fully-qualified type of a method's class (namespace-qualified when the source declares one). */
function qualifiedClass(m: DecisionMethod): string {
  return m.namespace ? `${m.namespace}.${m.className}` : m.className;
}

/** A C# expression that invokes the method on `argExpr`, unwrapping an async `Task<bool>` to a bool.
 *  Static → `Ns.Class.Method(arg)`; instance → `new Ns.Class().Method(arg)` (default ctor, else the
 *  isolated build fails and the method is skipped — an honest miss). */
function invokeExpr(m: DecisionMethod, argExpr: string): string {
  const q = qualifiedClass(m);
  const base = m.isStatic ? `${q}.${m.name}(${argExpr})` : `new ${q}().${m.name}(${argExpr})`;
  return m.isAsync ? `(${base}).GetAwaiter().GetResult()` : base;
}

/** True if the method returns a boolean decision (sync `bool` or async `Task<bool>`/`ValueTask<bool>`). */
function returnsBool(m: DecisionMethod): boolean {
  return m.retType === "bool" || m.retType === "Task<bool>" || m.retType === "ValueTask<bool>";
}

/**
 * Assemble Target.cs + a generated Driver.cs + a csproj into an isolated single-file project, build
 * it once, and run the driver. Returns the combined stdout/stderr, or "" if it did not build in
 * isolation (a file needing its project's deps → not drivable here; skip, never a false pass). Mirrors
 * CommandInjectionDotnetAttacker's build gate exactly (artifact existence, not build-text parsing).
 */
function buildAndRunDriver(source: string, driverProgram: string, sandbox: Sandbox, marker: string): string {
  const dir = `.rk-oracle-${marker}`;
  const asm = "rkoracle";
  sandbox.exec(`mkdir -p ${dir}`, 10_000);
  sandbox.writeFile(`${dir}/Target.cs`, source);
  sandbox.writeFile(`${dir}/Driver.cs`, driverProgram);
  sandbox.writeFile(`${dir}/drv.csproj`, dotnetDriverCsproj(asm));
  sandbox.exec(`${DOTNET_ENV} dotnet build ${dir}/drv.csproj -c Release -v quiet 2>&1`, 180_000);
  const dll = `${dir}/bin/Release/${dotnetTfm()}/${asm}.dll`;
  const check = sandbox.exec(`test -f ${dll} && echo RK_DLL_OK || echo RK_NO_DLL`, 10_000);
  if (!check.stdout.includes("RK_DLL_OK")) return "";
  const run = sandbox.exec(`${DOTNET_ENV} dotnet ${dll} 2>&1`, 30_000);
  return run.stdout + run.stderr;
}

/** Parse `RK_DIVERGENCE <json-encoded-string>` lines out of driver output. */
function parseDivergences(out: string): string[] {
  const hits: string[] = [];
  for (const line of out.split("\n")) {
    const m = line.match(/^RK_DIVERGENCE (.+)$/);
    if (!m) continue;
    try {
      hits.push(JSON.parse(m[1]));
    } catch {
      /* malformed → ignore */
    }
  }
  return hits;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shape 1 — command-approval differential oracle (the exec-approval class)
// ─────────────────────────────────────────────────────────────────────────────

export interface DotnetApprovalOracleSpec {
  readonly attackClass: AttackClassLike;
  readonly canaryFixtureDir: string;
  handles(file: string): boolean;
  /** Which decision method probes the approval belief — name filter over `bool <name>(string)`. */
  readonly methodName: RegExp;
  /** Adversarial command strings; `{{MARK}}` is replaced per-run by a fresh unguessable marker. */
  readonly corpus: readonly string[];
  readonly beliefLabel?: string;
  staticLeads?(source: string): StaticLead[];
}

// AttackClass/ExploitProof are string unions in ../types.js; alias here to avoid importing the whole
// union just to annotate (the runner supplies real members).
type AttackClassLike = Exploit["attackClass"];

/** The C# approval driver: for each baked-in corpus item, ask the gate (belief) then run the command
 *  (ground truth). Prints RK_DIVERGENCE for any item the gate approved that nonetheless ran the
 *  marker. The command runs via `/bin/sh -c` (POSIX sandbox); a benign `echo <marker>` is the proof. */
function buildApprovalDriver(m: DecisionMethod, corpus: readonly string[], marker: string): string {
  const corpusLiteral = corpus.map((c) => JSON.stringify(c.split("{{MARK}}").join(marker))).join(", ");
  return `using System;
using System.Diagnostics;
public static class __RaeuberDriver {
  const string MARK = ${JSON.stringify(marker)};
  static readonly string[] Corpus = new string[] { ${corpusLiteral} };
  static bool Believed(string input) {
    try { return ${invokeExpr(m, "input")}; } catch { return false; }
  }
  static bool GroundTruthFired(string input) {
    try {
      var psi = new ProcessStartInfo {
        FileName = "/bin/sh", RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false,
      };
      psi.ArgumentList.Add("-c"); psi.ArgumentList.Add(input);
      var p = Process.Start(psi);
      string outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
      p.WaitForExit();
      return outp.Contains(MARK);
    } catch { return false; }
  }
  public static void Main() {
    foreach (var input in Corpus) {
      if (!Believed(input)) continue;            // gate says unsafe -> it would prompt; not a bypass
      if (GroundTruthFired(input))
        Console.WriteLine("RK_DIVERGENCE " + System.Text.Json.JsonSerializer.Serialize(input));
    }
  }
}`;
}

/** Turn a command-approval oracle spec into a drive-and-prove C# Attacker lane. */
export function differentialOracleDotnet(spec: DotnetApprovalOracleSpec): Attacker {
  const label = spec.beliefLabel ?? "command-approval control";
  return {
    attackClass: spec.attackClass,
    canaryFixtureDir: spec.canaryFixtureDir,
    handles: (file) => spec.handles(file),
    staticLeads: (source) => (spec.staticLeads ? spec.staticLeads(source) : []),
    hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
      const exploits: Exploit[] = [];
      for (const file of files) {
        if (!spec.handles(file)) continue;
        let source: string;
        try {
          source = readFileSync(join(targetDir, file), "utf8");
        } catch {
          continue;
        }
        const method = csharpDecisionMethods(source).find(
          (m) => returnsBool(m) && m.firstParamType === "string" && spec.methodName.test(m.name),
        );
        if (!method) continue; // no `bool <name>(string)` decision to probe in this file
        const marker = freshMarker();
        const out = buildAndRunDriver(source, buildApprovalDriver(method, spec.corpus, marker), sandbox, marker);
        for (const input of parseDivergences(out)) {
          exploits.push({
            attackClass: spec.attackClass,
            proof: "belief-diverged",
            file,
            line: 1,
            sink: `belief:${label}`,
            summary:
              `The ${label} \`${method.className}.${method.name}()\` judged \`${input}\` safe/approved, but ` +
              `running it executed the benign marker — its belief diverges from actual behavior (a bypass of its own gate).`,
            payload: input,
            evidence: `belief=safe AND ground-truth fired the marker for: ${input}\n` + out.slice(0, 400),
          });
        }
      }
      return exploits;
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Shape 2 — authz fail-open oracle (differential authorization, CWE-862/863)
// ─────────────────────────────────────────────────────────────────────────────

export interface DotnetAuthzOracleSpec {
  readonly attackClass: AttackClassLike;
  readonly canaryFixtureDir: string;
  handles(file: string): boolean;
  /** Name filter over the authz decision method; defaults to the common gate verbs. */
  readonly methodName?: RegExp;
  readonly beliefLabel?: string;
  staticLeads?(source: string): StaticLead[];
}

// Default authz-decision method names: IsAuthorized/Authorize/HasPermission/CanX/IsAllowed/CheckAccess…
const DEFAULT_AUTHZ_NAME = /^(?:Is(?:Authori[sz]ed|Allowed|Permitted|Granted)|Authori[sz]e|Has(?:Permission|Role|Access|Scope)|Can[A-Z]\w*|CheckAccess|CheckAuthori[sz]ation|Ensure(?:Authori[sz]ed|Access))\w*$/;

// Principal-like first-parameter types we can construct as a NULL-authority caller in isolation.
const NULL_PRINCIPAL: Record<string, string> = {
  ClaimsPrincipal: "new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity())",
  ClaimsIdentity: "new System.Security.Claims.ClaimsIdentity()",
};

/** The authz driver: build the weakest-possible principal (unauthenticated, zero role/claim entries)
 *  and call the gate. A correct role/permission gate MUST deny it; RK_DIVERGENCE fires only when the
 *  gate returned true (admitted the null-authority caller = fail-open). No policy knowledge required. */
function buildAuthzDriver(m: DecisionMethod, principalExpr: string): string {
  return `using System;
public static class __RaeuberDriver {
  static bool Admitted() {
    try {
      var principal = ${principalExpr};
      return ${invokeExpr(m, "principal")};
    } catch { return false; }
  }
  public static void Main() {
    if (Admitted())
      Console.WriteLine("RK_DIVERGENCE " + System.Text.Json.JsonSerializer.Serialize("null-authority principal admitted by " + ${JSON.stringify(m.className + "." + m.name)}));
  }
}`;
}

/** Turn an authz fail-open oracle spec into a drive-and-prove C# Attacker lane. */
export function authzFailOpenDotnet(spec: DotnetAuthzOracleSpec): Attacker {
  const nameRe = spec.methodName ?? DEFAULT_AUTHZ_NAME;
  const label = spec.beliefLabel ?? "authorization control";
  return {
    attackClass: spec.attackClass,
    canaryFixtureDir: spec.canaryFixtureDir,
    handles: (file) => spec.handles(file),
    staticLeads: (source) => (spec.staticLeads ? spec.staticLeads(source) : []),
    hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
      const exploits: Exploit[] = [];
      for (const file of files) {
        if (!spec.handles(file)) continue;
        let source: string;
        try {
          source = readFileSync(join(targetDir, file), "utf8");
        } catch {
          continue;
        }
        const method = csharpDecisionMethods(source).find(
          (m) => returnsBool(m) && nameRe.test(m.name) && NULL_PRINCIPAL[m.firstParamType] !== undefined,
        );
        if (!method) continue; // no constructible `bool <authz-name>(ClaimsPrincipal)` gate here
        const marker = freshMarker();
        const out = buildAndRunDriver(source, buildAuthzDriver(method, NULL_PRINCIPAL[method.firstParamType]), sandbox, marker);
        for (const _hit of parseDivergences(out)) {
          exploits.push({
            attackClass: spec.attackClass,
            proof: "authz-fail-open",
            file,
            line: 1,
            sink: `authz:${label}`,
            summary:
              `The ${label} \`${method.className}.${method.name}(${method.firstParamType})\` admitted a NULL-authority ` +
              `principal (no roles or claims). A role/permission gate must deny the role-less caller; admitting it is ` +
              `a fail-open authorization bypass (CWE-862/863).`,
            payload: `${method.className}.${method.name}(new ClaimsPrincipal(new ClaimsIdentity())) === true`,
            evidence: `the gate returned true for an empty ClaimsPrincipal:\n` + out.slice(0, 400),
          });
        }
      }
      return exploits;
    },
  };
}

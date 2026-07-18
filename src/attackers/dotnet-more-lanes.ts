import type { Exploit } from "../types.js";
import type { AttackClass } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, scanSinkLeads } from "./attacker.js";
import { DOTNET_SOURCE_RE } from "./dotnet.js";

// Untrusted-input taint gate for C#: a file that surfaces gateway/remote input to the node. A sink in
// a file with NO such indicator (e.g. the SetupEngine writing its own config) is not attacker-reachable
// and is dropped — the lead-precision lesson (#10/#12) applied to the C# side.
export const UNTRUSTED_INPUT =
  /GetStringArg|GetIntArg|GetBoolArg|GetStringArrayArg|NodeInvokeRequest|request\.Args|\brequest\.|responseText|controlHost|HttpListenerContext|context\.Request|\bincoming\b|payload/;

/**
 * A static C# lane built from a sink regex (+ optional file-level taint gate). Feeds the sweep's
 * guard-consistency signal; the execute-gate skips it (staticOnly), proof is per-lead.
 */
class StaticDotnetLane implements Attacker {
  readonly staticOnly = true;
  readonly canaryFixtureDir = "";
  constructor(
    readonly attackClass: AttackClass,
    private readonly sinkRe: RegExp,
    private readonly requiresTaint = false,
  ) {}
  handles(file: string): boolean {
    return DOTNET_SOURCE_RE.test(file);
  }
  staticLeads(source: string): StaticLead[] {
    if (this.requiresTaint && !UNTRUSTED_INPUT.test(source)) return [];
    return scanSinkLeads(source, this.sinkRe);
  }
  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return [];
  }
}

// missing-authentication: an inbound HTTP endpoint/handler that performs an action. The sweep's
// guard-gap (no auth/token/signature reference in the file) is the sharpener — the node's local
// control/MCP HTTP servers are the target.
export const MissingAuthenticationDotnetAttacker = new StaticDotnetLane(
  "missing-authentication",
  /\bHttpListener\b|\.Map(?:Post|Get|Put|Delete)\s*\(|\[Http(?:Get|Post|Put|Delete)\b|HttpListenerContext\b|context\.Request\b|\.Run\s*\(\s*async\s*\(?context|IEndpointRouteBuilder\b/,
);

// resource-exhaustion / ReDoS: a Regex built or driven from a VARIABLE pattern (user-supplied) — a
// crafted pattern can catastrophically backtrack. Guard-gap = no match-timeout in the file.
export const ResourceExhaustionDotnetAttacker = new StaticDotnetLane(
  "resource-exhaustion",
  /\bnew\s+Regex\s*\(\s*[A-Za-z_]\w*(?![\w"])|\bRegex\.(?:Match|Matches|IsMatch|Replace|Split)\s*\(\s*[^,)]+,\s*[A-Za-z_]\w*\s*[,)]/,
);

// unsafe-exec: dynamic code / type / assembly loading — the C# analog of eval/new Function. Presence
// on a reachable path is the risk (no common sanitizer).
export const UnsafeExecDotnetAttacker = new StaticDotnetLane(
  "unsafe-exec",
  /\bCSharpScript\b|\bScriptOptions\b|\bAssembly\.Load(?:From|File)?\s*\(|\bType\.GetType\s*\(\s*[A-Za-z_]\w*|\bActivator\.CreateInstance\s*\(\s*(?:Type\.GetType|[A-Za-z_]\w*Type\b)|\bAppDomain\b[^;\n]*\.Load|\bDynamicMethod\b/,
);

// broken-object-access / IDOR: a resource reached by a caller-controlled id/key. Coarse — the taint
// gate requires a caller-supplied id/key in the file, guard-gap = no ownership check referenced.
export const BrokenObjectAccessDotnetAttacker = new StaticDotnetLane(
  "broken-object-access",
  /\.(?:TryGetValue|GetValueOrDefault)\s*\(\s*[A-Za-z_]\w*\s*[,)]|\bFirstOrDefault\s*\(\s*\w+\s*=>\s*\w+\.\w*(?:Id|Key|Name)\b\s*==|\b(?:Sessions?|_?store|_?entries|_?byId|_?map)\s*\[\s*[A-Za-z_]\w*\s*\]/,
  true,
);

// sql-injection: a query built by concatenation/interpolation rather than parameters. Guard = params.
export const SqlInjectionDotnetAttacker = new StaticDotnetLane(
  "sql-injection",
  /\.CommandText\s*=\s*[^;\n]*(?:\+|\$")|new\s+SqlCommand\s*\(\s*[^,)\n]*(?:\+|\$")|\bExecute(?:Reader|NonQuery|Scalar)\s*\(\s*[A-Za-z_]\w*\s*[,)]|\$@?"\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*\{/i,
);

// csv-injection: a value written to a CSV/spreadsheet cell. Guard = formula-prefix neutralization.
export const CsvInjectionDotnetAttacker = new StaticDotnetLane(
  "csv-injection",
  /\bWriteCsv\b|\bToCsv\b|\bCsvWriter\b|\bcsvEscape\b|\bAppendCsv\b|\.csv"\s*[,)]|string\.Join\s*\(\s*",",/,
  true,
);

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

// roslyn-security-scan: first-pass C#/.NET sink enumeration for CA3001-CA3012 / Security Code Scan
// families (command, SQL, LDAP, XPath, XSS, path tampering, deserialization/loader risk). This lane
// intentionally stays static-only and taint-gated, with targeted runtime proving planned per-sink in follow-on
// work where a real Roslyn graph is available.
export const DotnetSecurityScanAttacker = new StaticDotnetLane(
  "dotnet-security-scan",
  /Process\.Start\s*\(|new\s+ProcessStartInfo|\.CommandText\s*=|new\s+SqlCommand|\.Filter\s*=|\.SearchFilter\s*=|\.SearchScope\s*=\s*DirectoryScope|\.SelectNodes?\s*\(|\.SelectSingleNode\s*\(|XPathExpression\.Compile\s*\(|Execute(?:Query|Reader)\s*\(|Assembly\.Load(?:From|File)?\s*\(|AssemblyLoadContext\.Default\.LoadFromAssemblyPath\s*\(|\bBinaryFormatter\b|\bTypeNameHandling\b|\bXml(Text)?Reader\b|\.InnerHtml\s*=|\.WriteRaw\s*\(|\.WriteContent\s*\(|HttpUtility\.HtmlEncode|Path\.Combine\s*\(|File\.(?:ReadAll|WriteAll|AppendAll|Create|Open|Delete|Move|Copy)\s*\(|Path\.GetFullPath\s*\(/,
  true,
);

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

// broken-object-access / IDOR: a keyed collection lookup whose KEY is derived INLINE from untrusted
// input — `_store[GetStringArg(...)]`, `dict.TryGetValue(request.Args[...])`. This is the ONLY
// per-line IDOR signal a regex can trust: bare `TryGetValue` / `coll[i]` is how every C# dictionary
// and array is read (100s of benign internal-cache and loop-index hits — the prior coarse sink fired
// 179× on this repo, ~all noise). The two-line form (var id = GetStringArg(); _store[id]) is left to
// the sweep's guard-gap / #16 cross-file taint, NOT the sink — a deliberate recall-for-precision
// trade. On a single-user desktop node the cross-principal IDOR surface is inherently small, so a
// near-zero count here is the honest result, not a dead lane. Sink self-gates (no extra taint flag).
// The key must be an accessor CALL (`GetStringArg(`) or a request SUBSCRIPT (`request.Args[`) — never
// a bare property, so `new string[request.Args.Length]` (an allocation sized by an arg count) does
// NOT match, only a collection genuinely INDEXED by an untrusted key does.
export const BrokenObjectAccessDotnetAttacker = new StaticDotnetLane(
  "broken-object-access",
  /(?:\bTryGetValue|\bGetValueOrDefault)\s*\(\s*(?:GetString(?:Array)?Arg\s*\(|GetIntArg\s*\(|GetBoolArg\s*\(|request\.Args\s*\[|request\.Query\s*\[|context\.Request\b)|\[\s*(?:GetString(?:Array)?Arg\s*\(|GetIntArg\s*\(|request\.Args\s*\[|request\.Query\s*\[|context\.Request\b)/i,
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

// ── Breadth lanes (round 2): sink families the first cut didn't cover. Same StaticDotnetLane factory
// + sweep guard-consistency signal; staticOnly, proof is per-lead. The presence-of-a-dangerous-
// primitive lanes (insecure-tls, weak-crypto) intentionally SKIP the taint gate — the primitive
// itself is the risk regardless of input flow; the guard-gappable ones (xxe, zip-slip, webview-
// injection) lean on the sweep's SANITIZER_SIGNALS to surface the inconsistent site.

// insecure-tls: certificate validation disabled — an accept-any-cert callback or revocation turned
// off makes the node trust any TLS server (MITM). Assigning these callbacks in a *client* is almost
// always a downgrade; presence is the lead. No taint gate — the weakening is unconditional (CWE-295).
export const InsecureTlsDotnetAttacker = new StaticDotnetLane(
  "insecure-tls",
  /DangerousAcceptAnyServerCertificateValidator|ServerCertificateCustomValidationCallback\s*=|ServerCertificateValidationCallback\s*\+?=|RemoteCertificateValidationCallback\s*\+?=|CheckCertificateRevocationList\s*=\s*false/,
);

// weak-crypto: a broken primitive (MD5/SHA1 for security, DES/TripleDES/RC2, ECB, no padding). Some
// MD5/SHA1 uses are benign checksums — accepted noise this round; a regex can't read intent, so it's
// a lead, never a finding (CWE-327/328/326).
export const WeakCryptoDotnetAttacker = new StaticDotnetLane(
  "weak-crypto",
  /\bMD5\.Create\s*\(|\bSHA1\.Create\s*\(|new\s+MD5CryptoServiceProvider\b|new\s+SHA1(?:Managed|CryptoServiceProvider)\b|new\s+(?:DES|TripleDES|RC2)CryptoServiceProvider\b|\b(?:DES|TripleDES|RC2)\.Create\s*\(|CipherMode\.ECB\b|PaddingMode\.None\b/,
);

// xxe: XML parsed with DTD/external entities enabled. Guard-gap = the file doesn't set
// DtdProcessing.Prohibit / XmlResolver = null. Legacy XmlTextReader enabled DTD by default (CWE-611).
export const XxeDotnetAttacker = new StaticDotnetLane(
  "xxe",
  /DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+Xml(?:Url|Secure|Preloaded)?Resolver|new\s+XmlTextReader\s*\(/,
);

// insecure-temp-file: a predictable temp path used for sensitive data (race / symlink). Medium noise
// — GetTempPath is often benign; the guard-gap can't disambiguate, so it stays a lead (CWE-377).
export const InsecureTempFileDotnetAttacker = new StaticDotnetLane(
  "insecure-temp-file",
  /\bPath\.GetTempFileName\s*\(|\bPath\.GetTempPath\s*\(/,
);

// zip-slip (C#): an archive entry name reaches a Path.Combine/Join, or a manual ExtractToFile, with
// no containment. Guard-gap = no GetFullPath + root-prefix check in the file (CWE-22 archive variant).
export const ZipSlipDotnetAttacker = new StaticDotnetLane(
  "zip-slip",
  /\.FullName\b[^;\n]*Path\.(?:Combine|Join)|Path\.(?:Combine|Join)\s*\([^)]*\.FullName|\bExtractToFile\s*\(/,
);

// webview-injection: untrusted data concatenated/interpolated into a WebView ExecuteScriptAsync or
// NavigateToString — script/HTML injection into the trusted WebView origin. A literal-only call
// (no `$"`/`+`) won't match; the concat/interpolation shape is the signal. Guard-gap = no JSON/HTML
// encode in the file (CWE-79/94). Directly targets the canvas/chat WebView surfaces.
export const WebViewInjectionDotnetAttacker = new StaticDotnetLane(
  "webview-injection",
  /ExecuteScriptAsync\s*\(\s*(?:\$@?"|[A-Za-z_]\w*\s*\+|@?"[^"]*"\s*\+)|NavigateToString\s*\(\s*(?:\$@?"|[A-Za-z_]\w*\s*\+|@?"[^"]*"\s*\+)/,
);

// ── Round 3: weak-random, argument-injection, TOCTOU.

// weak-random: a non-cryptographic RNG (System.Random / Random.Shared) produces a SECURITY value —
// token/key/nonce/salt/otp/password/iv. `new Random()` is ubiquitous and mostly benign (UI, jitter),
// so the sink requires a security-shaped target ON THE LINE to stay out of the noise: a security-
// named var assigned from `new Random`, or a Random.Next(...) whose line names a security value.
// Guard-gap = the file uses RandomNumberGenerator (the crypto RNG that IS the fix) (CWE-330/338).
export const WeakRandomDotnetAttacker = new StaticDotnetLane(
  "weak-random",
  // 3 shapes: (1) a security-named var assigned from `new Random`; (2) ANY `.NextBytes(` — a
  // System.Random method (the crypto RNG uses .GetBytes/.Fill), so filling a buffer with it is the
  // weak-RNG-for-key/nonce tell regardless of the receiver var; (3) a Random.Next* on a security line.
  /(?:token|key|secret|nonce|salt|\biv\b|otp|password|passcode|\bpin\b|seed|session)\w*\s*=\s*[^;=\n]*\bnew\s+Random\b|\.NextBytes\s*\(|\b(?:new\s+Random\s*\([^)]*\)|Random\.Shared)\s*\.\s*Next\w*\b[^;\n]*(?:token|key|secret|nonce|salt|otp|password|passcode|\bpin\b)/i,
);

// argument-injection: untrusted data concatenated/interpolated into a process ARGUMENT string
// (ProcessStartInfo.Arguments), rather than the safe ArgumentList — a crafted value injects extra
// flags/args to the spawned program (distinct from shell command-injection; the program runs, but
// with attacker-added switches). Guard-gap = the file uses ArgumentList. Taint-gated (CWE-88).
export const ArgumentInjectionDotnetAttacker = new StaticDotnetLane(
  "argument-injection",
  /\.Arguments\s*=\s*[^;\n]*(?:\+|\$@?")|new\s+ProcessStartInfo\s*\(\s*[^,)\n]+,\s*[^)\n]*(?:\+|\$@?")/,
  true,
);

// toctou: a File.Exists / Directory.Exists used AS A CONDITION — the classic check-then-use race,
// where the path can change between the check and a later open/create/delete (esp. a symlink swap on
// an attacker-writable dir). Coarse lead: a reviewer confirms an unguarded use on the same path
// follows without an atomic handle. Taint-gated to files that surface untrusted input (CWE-367).
export const ToctouDotnetAttacker = new StaticDotnetLane(
  "toctou",
  /\bif\s*\(\s*!?\s*(?:File|Directory)\.Exists\s*\(/,
  true,
);

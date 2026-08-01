import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Exploit } from "../types.js";
import { type Sandbox, ensurePythonEnv } from "../sandbox.js";
import { type StaticLead, PYTHON_SOURCE_RE } from "./attacker.js";
import { type SecretBatteryItem, shq } from "./python-driver.js";

// Shared machinery for the secret-redaction lanes (#89 completeness, #91 mode-differential). Both
// discover a scrub/redact function and drive it with a battery of known secret formats, each carrying a
// format-VALID unguessable sentinel; a surviving sentinel proves that format leaked. Discovery + the
// battery live here; each lane supplies its own driver invocation and fire semantics.

const DEF_RE = /^def\s+([A-Za-z_]\w*)\s*\(\s*[A-Za-z_*]/gm;
const SCRUB_RE = /(?:redact|scrub|sanitiz|mask|censor|obfuscat|_secret|filter_secret|strip_secret)/i;
// A scrubber returns cleaned TEXT; exclude obvious non-text-returning verbs so we don't drive a checker.
const NON_SCRUB_RE = /(?:is_|has_|contains_|detect_|find_|count_)/i;

/** Names of scrub/redact functions in `source` (a redaction-ish name that returns cleaned text). */
function scrubberFunctions(source: string): string[] {
  const names: string[] = [];
  for (const m of source.matchAll(DEF_RE)) {
    const name = m[1] ?? "";
    if (SCRUB_RE.test(name) && !NON_SCRUB_RE.test(name)) names.push(name);
  }
  return [...new Set(names)];
}

/** The 1-based line of the first scrubber in `names`. */
function firstScrubberLine(source: string, names: Set<string>): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (m && names.has(m[1] ?? "")) return i + 1;
  }
  return 1;
}

/** Static leads: every scrubber definition line. */
export function scrubberLeads(source: string): StaticLead[] {
  const names = scrubberFunctions(source);
  if (names.length === 0) return [];
  const lines = source.split("\n");
  const leads: StaticLead[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (m && names.includes(m[1] ?? "")) leads.push({ line: i + 1, sink: `scrubber:${m[1]}()` });
  }
  return leads;
}

const hex = (n: number) => randomBytes(Math.ceil(n / 2)).toString("hex").slice(0, n);
const HEXU = (n: number) => hex(n).toUpperCase();

/**
 * A battery of known secret formats, each a format-VALID instance carrying an unguessable sentinel
 * substring (so embedding it does not break the pattern a scrubber matches). Fresh per call — the
 * sentinels are random, so a surviving sentinel cannot be a coincidence. Covers the crown-jewel formats
 * a real scrubber must catch: AWS id + secret key, GCP/PEM private key, Azure connection string,
 * Slack/GitHub/Stripe tokens, JWT, DB URL password, generic high-entropy env assignment.
 */
export function buildSecretBattery(): SecretBatteryItem[] {
  const items: SecretBatteryItem[] = [];
  const push = (label: string, sentinel: string, secret: string) => items.push({ label, sentinel, secret });

  const akiaBody = HEXU(16);
  push("aws-access-key-id", akiaBody, `AKIA${akiaBody}`);
  const awsSecret = hex(40);
  push("aws-secret-access-key", awsSecret, `aws_secret_access_key = ${awsSecret}`);
  const gh = hex(36);
  push("github-token", gh, `ghp_${gh}`);
  const slack = hex(24);
  push("slack-token", slack, `xoxb-2488888888-2900000000-${slack}`);
  const stripe = hex(24);
  push("stripe-secret-key", stripe, `sk_live_${stripe}`);
  const jwtMid = hex(20);
  push("jwt", jwtMid, `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI${jwtMid}In0.s5H${hex(10)}`);
  const dbpw = hex(18);
  push("db-url-password", dbpw, `postgres://app:${dbpw}@db.internal:5432/prod`);
  const pem = hex(40);
  push("pem-private-key", pem, `-----BEGIN PRIVATE KEY-----\nMIIEvQIBAD${pem}ANBg\n-----END PRIVATE KEY-----`);
  const azure = hex(32);
  push(
    "azure-connection-string",
    azure,
    `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${azure}==;EndpointSuffix=core.windows.net`,
  );
  const env = HEXU(24);
  push("generic-env-secret", env, `API_SECRET_TOKEN=${env}`);
  return items;
}

/**
 * A battery of CONFIG-secret assignment forms (env / yaml / json / ini), each carrying a high-entropy
 * unguessable sentinel — for the mode-differential lane (#91), which drives the SAME input across a
 * scrubber's context modes and fires when it is redacted in one mode but leaks in another. High-entropy
 * values only (a real secret), so a source-code reference (`os.getenv(...)`, a small integer) is never
 * a battery input — the mode difference that matters is a real secret leaking, not a code reference.
 */
export function buildConfigSecretBattery(): SecretBatteryItem[] {
  const items: SecretBatteryItem[] = [];
  const push = (label: string, sentinel: string, secret: string) => items.push({ label, sentinel, secret });
  push("env-assignment", hex(28), "");
  push("yaml-assignment", hex(28), "");
  push("json-assignment", hex(28), "");
  push("ini-assignment", hex(28), "");
  items[0]!.secret = `DB_PASSWORD=${items[0]!.sentinel}`;
  items[1]!.secret = `password: ${items[1]!.sentinel}`;
  items[2]!.secret = `{"password": "${items[2]!.sentinel}"}`;
  items[3]!.secret = `api_key = ${items[3]!.sentinel}`;
  return items;
}

export interface ScrubberDriveSpec<TInfo> {
  /** Regex over each driver output line; capture group 1 = fnName, group 2 = JSON info. */
  marker: RegExp;
  /** Build the per-file driver: its sandbox-relative filename and body. */
  buildDriver(file: string, names: string[]): { rel: string; body: string };
  /** Turn one `marker`-matched leak line into an Exploit. */
  buildExploit(ctx: { file: string; fnName: string; info: TInfo; scrubberLine: number; output: string }): Exploit;
}

/**
 * Shared drive-and-prove loop for the Python scrubber lanes (redaction-completeness #89 and
 * redaction-mode-differential #91). Sets up the Python env, iterates handled files, discovers scrubber
 * functions, drives a lane-specific driver, and turns each `marker`-matched leak line into an Exploit
 * via `buildExploit`. The lanes differ only in battery/driver, output marker, and exploit shape — the
 * env setup, file iteration, scrubber discovery, and per-(file,fn,label) dedup live here once.
 */
export function scrubberDriveHunt<TInfo extends { label: string }>(
  targetDir: string,
  files: string[],
  sandbox: Sandbox,
  spec: ScrubberDriveSpec<TInfo>,
): Exploit[] {
  const exploits: Exploit[] = [];
  const py = ensurePythonEnv(sandbox, targetDir);
  const seen = new Set<string>();
  for (const file of files) {
    if (!PYTHON_SOURCE_RE.test(file)) continue;
    let source: string;
    try {
      source = readFileSync(join(targetDir, file), "utf8");
    } catch {
      continue;
    }
    const names = scrubberFunctions(source);
    if (names.length === 0) continue;
    const scrubberLine = firstScrubberLine(source, new Set(names));

    const { rel, body } = spec.buildDriver(file, names);
    sandbox.writeFile(rel, body);
    const out = sandbox.exec(`${py} ${shq(rel)} 2>&1`, 30_000);
    const output = out.stdout + out.stderr;
    for (const line of output.split("\n")) {
      const m = line.match(spec.marker);
      if (!m) continue;
      const fnName = m[1] as string;
      let info: TInfo;
      try {
        info = JSON.parse(m[2] ?? "") as TInfo;
      } catch {
        continue;
      }
      const key = `${file}::${fnName}::${info.label}`;
      if (seen.has(key)) continue;
      seen.add(key);
      exploits.push(spec.buildExploit({ file, fnName, info, scrubberLine, output }));
    }
  }
  return exploits;
}

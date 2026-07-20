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

const HERE = dirname(fileURLToPath(import.meta.url));

// Secondary interpreter sinks:
// - SSTI/template sinks (`render` / `compile` call chains)
// - log sinks (`console.log`, logger-style methods)
// - response-header sinks (`setHeader` / `writeHead` / `set` / `header`)
// - CSV formula sinks (overlapping with the existing csv lane; this lane adds family context)
const SSTI_RE =
  /\b(?:res\.)?render\b|\b\w+\.(?:render(?:String|ToString|File)?|compile(?:File)?|template)\s*\(|\b(?:render|compile|renderString|renderToString|template)\s*\(|\b(?:handlebars|mustache|ejs|eta|nunjucks)\b\s*\.\s*(?:render|compile|compileString|renderString)\s*\(/i;
const LOG_RE =
  /\bconsole\.(?:log|info|warn|error|debug|trace|fatal)\(|\b(?:log|logger|winston|pino)\.[a-zA-Z_$][\w$]*\s*\(|\b[a-zA-Z_$][\w$]*\.(?:log|info|warn|error|debug|trace|fatal)\s*\(/i;
const HEADER_RE = /\b\w*\.(?:setHeader|writeHead|set|header)\s*\(|\b(?:setHeader|writeHead|set|header)\s*\(/i;
const CSV_RE = /\.(?:join\((['"]).*?\1\)|unparse\(|csv[_-]?stringify|stringify\([^)]*\b(?:columns|header|delimiter)\b|(?:writeFileSync?|createWriteStream)\s*\([^)]*\.csv)/i;

const TARGETS = [
  { family: "ssti", re: SSTI_RE },
  { family: "log", re: LOG_RE },
  { family: "header", re: HEADER_RE },
  { family: "csv", re: CSV_RE },
] as const;

type TargetFamily = (typeof TARGETS)[number]["family"];
type ProbePayload = { kind: TargetFamily; variant: string; payload: string };

type ProofKind = "marker-executed" | "formula-unescaped";

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    for (const target of TARGETS) {
      if (target.re.test(lines[i])) return i + 1;
    }
  }
  return 1;
}

function firstSinkToken(source: string): string {
  for (const line of source.split("\n")) {
    for (const target of TARGETS) {
      const m = line.match(target.re);
      if (m && m[0]) {
        return `${target.family}(${m[0].split("(")[0].trim()})`;
      }
    }
  }
  return "secondary-interpreter";
}

function staticLeadsFromSource(source: string): StaticLead[] {
  const leads: StaticLead[] = [];
  for (const target of TARGETS) {
    const grouped = scanSinkLeads(source, target.re).map((lead) => ({
      ...lead,
      sink: `${target.family}(${lead.sink})`,
    }));
    leads.push(...grouped);
  }
  return leads;
}

function probeTemplate(moduleRel: string, fnName: string, marker: string): string {
  const MOD = JSON.stringify("./" + moduleRel);
  const FN = JSON.stringify(fnName);
  return `
const MARKER = ${JSON.stringify(marker)};
const modRel = ${MOD};
const fnName = ${FN};

const sstiPayloads = ["{{value}}", "<%= value %>", "{{{value}}}", "{{ value }}"];
const logPayload = "line-start\\n" + MARKER;
const headerPayload = "https://example.com/\\r\\nX-Injected: " + MARKER;
const csvPayloads = ["=" + MARKER, "+" + MARKER, "-" + MARKER, "@" + MARKER];

let m;
try {
  m = await import(modRel);
} catch (e) {
  process.stdout.write("IMPORT_FAIL:" + e);
  process.exit(0);
}

const target = (m && m[fnName]) || (m && m.default && (m.default[fnName] || m.default));
if (typeof target !== "function") {
  process.stdout.write("NOT_A_FUNCTION");
  process.exit(0);
}

const logs = [];
const headers = [];
const orig = {};
for (const k of ["log", "info", "warn", "error", "debug", "trace", "fatal"]) {
  orig[k] = console[k];
  console[k] = (...args) => {
    logs.push(args.map((x) => String(x ?? "")).join(" "));
  };
}

const fakeRes = {
  setHeader(name, value) {
    headers.push([String(name), String(value)]);
  },
  writeHead(code, statusOrHeaders, headersMap) {
    const candidate = typeof statusOrHeaders === "object" ? statusOrHeaders : headersMap;
    if (candidate && typeof candidate === "object") {
      for (const [k, v] of Object.entries(candidate)) {
        headers.push([String(k), String(v)]);
      }
    }
  },
  set(name, value) {
    headers.push([String(name), String(value)]);
  },
  header(name, value) {
    if (arguments.length >= 2) {
      headers.push([String(name), String(value)]);
      return;
    }
    if (name && typeof name === "object") {
      for (const [k, v] of Object.entries(name)) headers.push([String(k), String(v)]);
    }
  },
  addHeader(name, value) {
    headers.push([String(name), String(value)]);
  },
};

function asText(v) {
  if (v == null) return "";
  if (v instanceof Error) return v.message || String(v);
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  if (v.stdout && typeof v.stdout === "string") return v.stdout;
  try {
    return typeof v === "string" ? v : JSON.stringify(v) || String(v);
  } catch {
    return String(v);
  }
}

function restore() {
  for (const k of ["log", "info", "warn", "error", "debug", "trace", "fatal"]) {
    console[k] = orig[k];
  }
}

async function runWith(args) {
  logs.length = 0;
  headers.length = 0;
  let output = "";
  try {
    const value = await target(...args);
    output = asText(value);
  } catch (e) {
    output = asText(e);
  }
  const text = output + "\n" + logs.join("\n") + "\n" + headers.map((h) => h.join("=")).join("\n");
  return { output, text, headers: [...headers], logs: [...logs] };
}

function hasMarker(v) {
  return asText(v).includes(MARKER);
}

function hasForgedLog(v) {
  return v.logs.some((x) => String(x).includes(MARKER) && /\r|\n/.test(String(x)));
}

function hasCrlfHeader(v) {
  return v.headers.some((pair) => {
    const h = String(pair[1] || "");
    return h.includes(MARKER) && /\r|\n/.test(h);
  });
}

function hasFormulaCell(v) {
  for (const line of asText(v).split(/\r?\n/)) {
    for (const cell of line.split(",")) {
      const c = String(cell).replace(/^\s*["']/, "").replace(/["']\s*$/, "");
      if (/^[=+@-]/.test(c) && c.includes(MARKER)) return true;
    }
  }
  return false;
}

async function tryProbe(kind, variant, args, test) {
  const out = await runWith(args);
  if (test(out)) {
    process.stdout.write("SI_FIRED " + JSON.stringify({ kind, variant, payload: JSON.stringify(args[0]) }));
    process.stdout.write(" \n" + out.text.slice(0, 900));
    return true;
  }
  return false;
}

try {
  for (const p of sstiPayloads) {
    if (await tryProbe("ssti", "template", [p, { value: MARKER }], (o) => hasMarker(o.output) || hasMarker(o.text))) {
      throw 0;
    }
    if (await tryProbe("ssti", "template-ctx", [{ template: p }, { value: MARKER }], (o) => hasMarker(o.output) || hasMarker(o.text))) {
      throw 0;
    }
  }

  if (await tryProbe("log", "console", [logPayload], (o) => hasForgedLog(o))) {
    throw 0;
  }

  const reqLike = { url: MARKER, query: MARKER, body: { next: MARKER } };
  const withPayload = [reqLike, fakeRes, headerPayload];

  for (const payload of csvPayloads) {
    if (await tryProbe("csv", "join", [payload], (o) => hasFormulaCell(o.output) || hasFormulaCell(o.text))) {
      throw 0;
    }
    if (await tryProbe("csv", "row", [[payload]], (o) => hasFormulaCell(o.output) || hasFormulaCell(o.text))) {
      throw 0;
    }
  }

  if (await tryProbe("header", "setHeader", [fakeRes, headerPayload], (o) => hasCrlfHeader(o))) {
    throw 0;
  }
  if (await tryProbe("header", "writeHead", [fakeRes, 302, { location: headerPayload }], (o) => hasCrlfHeader(o))) {
    throw 0;
  }
  if (await tryProbe("header", "set", [fakeRes, "Location", headerPayload], (o) => hasCrlfHeader(o))) {
    throw 0;
  }
  if (await tryProbe("header", "header", [fakeRes, { location: headerPayload }], (o) => hasCrlfHeader(o))) {
    throw 0;
  }
  if (await tryProbe("header", "req-res", withPayload, (o) => hasCrlfHeader(o))) {
    throw 0;
  }

  process.stdout.write("SI_SAFE");
} finally {
  restore();
}
`.trim();
}

export class SecondaryInterpreterAttacker implements Attacker {
  readonly attackClass = "secondary-interpreter" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "secondary-interpreter-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return staticLeadsFromSource(source);
  }

  hunt(targetDir: string, files: string[], sandbox: Sandbox): Exploit[] {
    const exploits: Exploit[] = [];
    for (const file of files) {
      if (!this.handles(file)) continue;

      let source = "";
      try {
        source = readFileSync(join(targetDir, file), "utf8");
      } catch {
        continue;
      }
      if (!TARGETS.some((t) => t.re.test(source))) continue;

      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      const sinkLine = firstSinkLine(source);
      const sink = firstSinkToken(source);

      let fired = false;
      for (const name of names) {
        if (fired) break;

        const marker = freshMarker();
        const driver = `.raeuber-secondary-${marker}.mjs`;
        sandbox.writeFile(driver, probeTemplate(file, name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driver} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        const m = out.match(/SI_FIRED (\{[^]*\})/);
        if (!m) continue;

        let payload: ProbePayload;
        try {
          payload = JSON.parse(m[1] as string) as ProbePayload;
        } catch {
          continue;
        }
        if (!payload.kind) continue;

        const proof: ProofKind = payload.kind === "csv" ? "formula-unescaped" : "marker-executed";
        const summary =
          payload.kind === "ssti"
            ? `Untrusted value reached a template/render sink (` +
              `${payload.variant || "template"}) and returned marker-controlled output; template evaluation is reachable.`
            : payload.kind === "log"
              ? `Untrusted value reached a log sink (` +
                `${payload.variant || "console"}) and could forge output via CR/LF in log data.`
              : payload.kind === "header"
                ? `Untrusted value reached a header sink (` +
                  `${payload.variant || "header"}) and introduced CRLF into a response-header value.`
                : `Untrusted value reached CSV output and remained formula-prefixed (` +
                  `${payload.variant || "join"}); a formula payload survived un-escaped.`;

        exploits.push({
          attackClass: "secondary-interpreter",
          proof,
          file,
          line: sinkLine,
          sink,
          summary,
          payload: (() => {
            try {
              const decoded = JSON.parse(payload.payload);
              return typeof decoded === "string" ? decoded : JSON.stringify(decoded);
            } catch {
              return payload.payload ?? "";
            }
          })(),
          evidence: out.slice(0, 900),
        });
        fired = true;
      }
    }
    return exploits;
  }
}

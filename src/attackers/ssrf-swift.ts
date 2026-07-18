import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, freshMarker, scanSinkLeads } from "./attacker.js";
import { SWIFT_SOURCE_RE, swiftCallExpr, swiftDrivableFunctions } from "./swift.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// An SSRF sink in Swift: an outbound request task whose URL is built from a variable. A lead, not a
// finding — whether the *host* is attacker-influenced is what the PoC decides.
const SINK_RE =
  /\bdataTask\s*\(|\.data\s*\(\s*(?:for|from):|\bdownloadTask\s*\(|\buploadTask\s*\(|\bNSURLConnection\b/;

// The request URL is built from a variable (`URL(string: v)`, an interpolated string, or a
// concatenation) rather than a fixed literal — the tainted shape that can be redirected to a
// loopback/internal host.
const TAINT_RE =
  /URL\s*\(\s*string:\s*[A-Za-z_]|URL\s*\(\s*string:\s*["'][^"'\n]*\\\(|\\\(|["'][^"'\n]*["']\s*\+\s*[A-Za-z_]/;

/**
 * A `main.swift` driver that PROVES SSRF with an out-of-band signal and zero external network: it
 * starts a throwaway TCP listener on `127.0.0.1:<ephemeral>` (POSIX sockets — no server dependency),
 * calls the target entrypoint with a loopback URL carrying the per-run marker in its path, then waits.
 * If the entrypoint makes the request, the listener sees the marker → `oob-request` fired. The marker
 * cannot arrive by coincidence and nothing leaves the box. (v1 drives the raw-URL-argument shape; a
 * sink that appends the argument to a FIXED `https://host` prefix needs the `@`-userinfo trick over
 * TLS, which a plain loopback can't answer — an honest limitation, like the Node lane's low-ranked
 * fixed-host leads.)
 */
function swiftSsrfDriverMain(fnCall: string): string {
  return `import Foundation

func __rkStartListener(marker: String, onHit: @escaping () -> Void) -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    _ = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    listen(fd, 4)
    var actual = sockaddr_in()
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &actual) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
    }
    let port = UInt16(bigEndian: actual.sin_port)
    Thread.detachNewThread {
        while true {
            let client = accept(fd, nil, nil)
            if client < 0 { break }
            var buf = [UInt8](repeating: 0, count: 2048)
            let n = read(client, &buf, buf.count)
            if n > 0, let s = String(bytes: buf[0..<n], encoding: .utf8), s.contains(marker) { onHit() }
            let resp = "HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n"
            _ = resp.withCString { write(client, $0, strlen($0)) }
            close(client)
        }
    }
    return port
}

let __rk_marker = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "MARK"
let __rk_sema = DispatchSemaphore(value: 0)
var __rk_fired = false
let __rk_port = __rkStartListener(marker: __rk_marker) { __rk_fired = true; __rk_sema.signal() }
let __rk_url = "http://127.0.0.1:\\(__rk_port)/\\(__rk_marker)"
_ = ${fnCall}
_ = __rk_sema.wait(timeout: .now() + 4)
print(__rk_fired ? "OOB_FIRED:\\(__rk_marker)" : "no-oob", terminator: "")
`;
}

function firstSinkLine(source: string): number {
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) if (SINK_RE.test(lines[i])) return i + 1;
  return 1;
}

/**
 * The Swift SSRF lane. Same contract as the family — a finding is a request that actually FIRED at a
 * loopback listener (`oob-request`), never a static "the URL is variable". Drives a compiled Swift
 * entrypoint (first `String` arg = the URL) built together with the OOB driver above; a file needing
 * the rest of its package won't build in isolation (an honest miss). Runs on the macOS host.
 */
export class SsrfSwiftAttacker implements Attacker {
  readonly attackClass = "ssrf" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "ssrf-swift");

  handles(file: string): boolean {
    return SWIFT_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    if (!TAINT_RE.test(source)) return []; // fixed-literal request URL → not redirectable
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
      if (!SINK_RE.test(source)) continue; // no outbound-request sink
      if (!TAINT_RE.test(source)) continue; // request URL is a fixed literal — not redirectable
      const fns = swiftDrivableFunctions(source);
      if (fns.length === 0) continue;
      const sinkLine = firstSinkLine(source);
      const sink = (source.match(SINK_RE)?.[0] ?? "dataTask").replace(/\s*\($/, "").trim();

      let fired = false;
      for (const fn of fns) {
        if (fired) break;
        const marker = freshMarker();
        const dir = `.rk-swift-${marker}`;
        const bin = `${dir}/drv`;

        sandbox.exec(`mkdir -p ${dir}`, 10_000);
        sandbox.writeFile(`${dir}/Target.swift`, source);
        sandbox.writeFile(`${dir}/main.swift`, swiftSsrfDriverMain(swiftCallExpr(fn, "__rk_url")));

        sandbox.exec(`swiftc -suppress-warnings ${dir}/Target.swift ${dir}/main.swift -o ${bin} 2>&1`, 180_000);
        const check = sandbox.exec(`test -f ${bin} && echo RK_BIN_OK || echo RK_NO_BIN`, 10_000);
        if (!check.stdout.includes("RK_BIN_OK")) continue;

        const run = sandbox.exec(`./${bin} ${marker} 2>&1`, 30_000);
        const out = run.stdout + run.stderr;
        // Fired = the entrypoint fetched the loopback URL and the listener saw the marker in the path.
        if (out.includes(`OOB_FIRED:${marker}`)) {
          const receiver = fn.enclosingType ? `${fn.enclosingType}.${fn.name}` : fn.name;
          exploits.push({
            attackClass: "ssrf",
            proof: "oob-request",
            file,
            line: sinkLine,
            sink,
            summary: `Untrusted first argument of \`${receiver}()\` controls an outbound request host; a loopback URL was fetched.`,
            payload: `http://127.0.0.1:<port>/${marker}`,
            evidence:
              `driver invoked ${receiver}() with a 127.0.0.1 loopback URL; the in-sandbox listener ` +
              `received the marker ${marker} — the request reached an attacker-chosen host:\n` +
              out.slice(0, 400),
          });
          fired = true;
        }
      }
    }
    return exploits;
  }
}

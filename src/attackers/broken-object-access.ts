import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, nodeRunCommand, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";
import { functionUnits } from "./broken-access-control.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Broken object-level authorization (IDOR / BOLA, CWE-639/284): an entrypoint resolves a resource from
// a CALLER-CONTROLLED key (`p.id`, `p.key`, `p.agentId`) and returns/mutates it WITHOUT checking that
// the caller owns it — so principal B reads principal A's object by supplying A's key. Unlike
// broken-access-control (wrong scope TIER), the two callers here hold the SAME scope; what differs is
// object OWNERSHIP. The find is a guard-gap (a read/lookup-by-key with no ownership check); the proof is
// differential: create a resource as identity A, reach it as identity B, and see A's marker come back.

// The project's own ownership/tenancy guard — its presence on a lookup path is what makes access safe.
const OWNERSHIP_GUARD_RE =
  /\.owner\b|ownerId|ownedBy|belongsTo|isOwnedBy|sameTenant|tenantId|resolveRequested\w*(?:Agent|User|Owner)\w*|assert\w*(?:Owner|Tenant|Access|Membership)|verify\w*(?:Owner|Access)|require\w*Owner|\bidentity\s*===|\bcallerId\b|principal\b/i;

// A lookup/mutation of a resource BY a key — the object-access sink.
const RESOURCE_SINK_RE =
  /\b(?:load|get|fetch|find|read|lookup|resolve|open|select)\w*(?:By(?:Id|Key)|Entry|Session|Record|Document|Doc|File|Resource|Object|Item)\w*\s*\(|\b(?:docs|store|records|sessions|entries|resources|objects|items|db)\s*\[\s*[A-Za-z_$]/i;

// Verb hints for pairing a WRITE-then-READ probe (create a resource, then read it back as another id-holder).
const CREATE_RE = /^(?:create|add|new|make|register|save|store|insert|put|upload|generate|issue|mint)/i;
const READ_RE = /^(?:get|read|fetch|load|find|lookup|describe|show|view|open|resolve|download|export|inspect)/i;

interface Entry {
  name: string;
  line: number;
  body: string;
  hasOwnerGuard: boolean;
  reachesKeyedResource: boolean;
}

/**
 * Drive an IDOR probe: create a resource as identity A (carrying a fresh marker), then reach it as a
 * DIFFERENT identity B through the candidate read entrypoint. Fired = B got A's marker back (or an
 * A-owned object) — object-level authorization was never enforced. A read that throws an
 * ownership/authorization error for B is the safe (non-fired) case.
 */
function idorDiffDriver(moduleRel: string, createName: string, readName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const C = JSON.stringify(createName);
  const R = JSON.stringify(readName);
  const MK = JSON.stringify(marker);
  return `
const MARKER = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const create = pick(${C}), read = pick(${R});
if (!create || !read) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
function idsAll(v, out){ if (v==null) return; if (typeof v==="string"){ out.push(v); return; } if (typeof v==="object"){ for (const k of Object.keys(v)){ if (/^(id|key|sessionId|sessionKey|docId|resourceId|name|_id)$/i.test(k) && (typeof v[k]==="string"||typeof v[k]==="number")) out.push(String(v[k])); idsAll(v[k], out); } } }
function ctxs(identity){ const s=["read","write"]; return [ {identity, scopes:s}, {agentId:identity, scopes:s}, {userId:identity, scopes:s}, {caller:{id:identity}, scopes:s}, {user:{id:identity}, scopes:s}, {identity} ]; }
const BODY = { body: MARKER, content: MARKER, text: MARKER, value: MARKER, data: MARKER, name: MARKER, message: MARKER };
function isAuthzErr(e){ const t=String((e&&((e.name||"")+" "+(e.message||"")))||e||"").toLowerCase(); return /(authz|unauthor|forbidden|denied|permission|not allowed|not.?the.?owner|owner|access|403)/.test(t); }
async function call(fn, args){ try { return { ok:true, ret: await fn(...args) }; } catch(e){ return { ok:false, authz:isAuthzErr(e) }; } }
// 1) create a victim resource as ALICE
let victimIds = [];
for (const actx of ctxs("alice-"+MARKER.slice(0,6))){
  const r = await call(create, [actx, BODY]);
  if (r.ok){ idsAll(r.ret, victimIds); if (victimIds.length) break; }
}
if (!victimIds.length){ process.stdout.write("no-victim-id"); process.exit(0); }
// 2) reach it as BOB (a different identity that never created it)
for (const bctx of ctxs("bob-"+MARKER.slice(0,6))){
  for (const id of victimIds){
    const r = await call(read, [bctx, id]);
    if (r.ok){
      let s=""; try { s = JSON.stringify(r.ret); } catch { s = String(r.ret); }
      if (s.indexOf(MARKER) !== -1){ process.stdout.write("IDOR_FIRED read="+${R}+" victimId="+id+" leaked="+s.slice(0,120)); process.exit(0); }
    }
  }
}
process.stdout.write("no-idor");
`.trim();
}

export class BrokenObjectAccessAttacker implements Attacker {
  readonly attackClass = "broken-object-access" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "broken-object-access-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    // Leads = resource-lookup-by-key sinks; the guard-gap (a lookup whose entrypoint lacks an ownership
    // check) is what the hunt proves. A lone lookup is not a finding — ownership may be enforced elsewhere.
    return scanSinkLeads(source, RESOURCE_SINK_RE);
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
      if (!RESOURCE_SINK_RE.test(source)) continue; // no resource-by-key access here
      const exported = new Set(nodeExportedNames(source));
      const entries: Entry[] = functionUnits(source)
        .filter((u) => exported.has(u.name))
        .map((u) => ({
          name: u.name,
          line: u.line,
          body: u.body,
          hasOwnerGuard: OWNERSHIP_GUARD_RE.test(u.body),
          reachesKeyedResource: RESOURCE_SINK_RE.test(u.body),
        }));

      // A read entrypoint that resolves a resource from a caller key WITHOUT an ownership guard = gap.
      const readGaps = entries.filter((e) => READ_RE.test(e.name) && e.reachesKeyedResource && !e.hasOwnerGuard);
      if (readGaps.length === 0) continue;
      const creators = entries.filter((e) => CREATE_RE.test(e.name));
      if (creators.length === 0) continue; // need a create path to plant a victim resource to prove against

      let fired = false;
      for (const read of readGaps) {
        if (fired) break;
        for (const create of creators) {
          const marker = freshMarker();
          const driverRel = `.raeuber-idor-${marker}.mjs`;
          sandbox.writeFile(driverRel, idorDiffDriver(file, create.name, read.name, marker));
          const run = sandbox.exec(`${nodeRunCommand(targetDir)} ${driverRel} 2>&1`, 15_000);
          const out = run.stdout + run.stderr;
          if (!out.includes("IDOR_FIRED")) continue;
          exploits.push({
            attackClass: "broken-object-access",
            proof: "foreign-object-accessed",
            file,
            line: read.line,
            sink: `object-access(${read.name})`,
            summary:
              `Exported \`${read.name}()\` resolves a resource from a caller-controlled key and returns it without an ownership check; a resource created by one identity via \`${create.name}()\` was read back by a DIFFERENT identity (IDOR / broken object-level authorization, CWE-639).`,
            payload: `${create.name}({identity:"alice"}, {body:"${marker}"}) → ${read.name}({identity:"bob"}, <alice's id>)`,
            evidence:
              `driver created a resource as identity "alice" (marker ${marker}), then reached it via ` +
              `\`${read.name}()\` as identity "bob" — bob received alice's marker:\n` +
              out.slice(0, 700),
          });
          fired = true;
          break;
        }
      }
    }
    return exploits;
  }
}

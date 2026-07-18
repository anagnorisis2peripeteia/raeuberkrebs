import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, NODE_RUN, NODE_SOURCE_RE, freshMarker, nodeExportedNames, scanSinkLeads } from "./attacker.js";
import { functionUnits } from "./broken-access-control.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Missing authentication on an inbound path (CWE-306) / sender spoofing (CWE-290): a webhook or channel
// INGRESS handler performs a privileged/state-changing action on a request WITHOUT verifying the
// request signature or authenticating the sender. So a forged (unsigned, spoofed) request drives the
// action. The find is a guard-gap (an ingress handler reaching an action with no signature/sender
// check its siblings apply); the proof is a FIRED forged request — an unauthenticated marker action
// the handler accepted and processed.

// The project's own request-authentication guard — its presence on the path is what makes ingress safe.
const AUTH_GUARD_RE =
  /verif\w*(?:Signature|Webhook|Hmac|Hub|Token|Secret|Sender|Request|Payload|Slack|Origin)|createHmac|timingSafeEqual|\bhmac\b|validate\w*(?:Signature|Webhook|Token|Request)|check\w*(?:Signature|Auth|Sender|Token)|assert\w*(?:Auth|Signature|Sender|Verified)|x-hub-signature|x-slack-signature|x-signature|isAuthorized|isAdmin\b|allowed(?:Senders?|Chats?|Users?)|allow(?:list|From)|authenticate|requireAuth|constantTime|sharedSecret\s*===|\bsecret\s*===/i;

// The entrypoint looks like an inbound handler (name or a request-shaped first read).
const INGRESS_NAME_RE = /webhook|ingress|inbound|callback|(?:handle|on|process|receive|ingest)\w*(?:Update|Message|Event|Notification|Push|Hook|Request|Payload)/i;
const REQUEST_SHAPE_RE = /\b(?:req|request|update|payload|event|body|ctx)\s*\.\s*(?:body|headers|message|update|from|sender|payload|params|rawBody|signature)\b/i;

// The handler reaches a privileged / state-changing action worth protecting.
const ACTION_RE =
  /\b(?:dispatch|execute|run|invoke|apply|handle|process|perform|trigger|enqueue|forward)(?:Command|Action|Message|Update|Task|Job|Event)?\w*\s*\(|\.(?:send|post|write|update|delete|create|set|save|persist|exec|run|reply|emit|mutate|append)\w*\s*\(|sendMessage\s*\(/i;

interface Entry {
  name: string;
  line: number;
  body: string;
  isIngress: boolean;
  hasAuthGuard: boolean;
  reachesAction: boolean;
}

/**
 * Drive a FORGED inbound request — no valid signature, spoofed/absent sender — carrying a benign marker
 * action through the handler, in several plausible request shapes. Fired = the handler ACCEPTED and
 * processed the marker (it appears in the return) without throwing an authentication/signature error.
 * A handler that rejects the unsigned request (throws an auth/signature error) is the safe case.
 */
function forgedIngressDriver(moduleRel: string, handlerName: string, marker: string): string {
  const mod = JSON.stringify("./" + moduleRel);
  const H = JSON.stringify(handlerName);
  const MK = JSON.stringify(marker);
  return `
const MARKER = ${MK};
let m;
try { m = await import(${mod}); } catch (e) { process.stdout.write("IMPORT_FAIL:" + e); process.exit(0); }
function pick(n){ if (m && typeof m[n]==="function") return m[n]; if (m && m.default && typeof m.default[n]==="function") return m.default[n]; return null; }
const h = pick(${H});
if (!h) { process.stdout.write("NOT_A_FUNCTION"); process.exit(0); }
const A = { action: MARKER, command: MARKER, text: MARKER, body: MARKER, data: MARKER, message: MARKER, cmd: MARKER, type: MARKER };
// Forged requests: no signature / an obviously-wrong one / a spoofed sender.
const reqs = [
  { headers: {}, body: A },
  { headers: { "x-signature": "forged", "x-hub-signature-256": "sha256=forged" }, body: A },
  { body: A },
  { message: { text: MARKER, chat: { id: 1 }, from: { id: 999999, is_bot: false } } },
  { update: { message: { text: MARKER, from: { id: 999999 } } } },
  { payload: A, headers: {} },
  { rawBody: JSON.stringify(A), headers: {}, body: A },
  A,
];
function isAuthErr(e){ const t=String((e&&((e.name||"")+" "+(e.message||"")))||e||"").toLowerCase(); return /(signature|unauthenticated|unauthor|forbidden|denied|invalid|not allowed|verify|verif|auth|spoof|secret|token|sender|403|401)/.test(t); }
let rejected = 0;
for (const req of reqs){
  let r;
  try { r = await h(req); }
  catch (e){ if (isAuthErr(e)) rejected++; continue; }
  let s=""; try { s = typeof r === "string" ? r : JSON.stringify(r); } catch { s = String(r); }
  if (s && s.indexOf(MARKER) !== -1){ process.stdout.write("NOAUTH_FIRED handler="+${H}+" via="+JSON.stringify(Object.keys(req))+" out="+s.slice(0,120)); process.exit(0); }
}
process.stdout.write("no-noauth rejected="+rejected);
`.trim();
}

export class MissingAuthenticationAttacker implements Attacker {
  readonly attackClass = "missing-authentication" as const;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "missing-authentication-node");

  handles(file: string): boolean {
    return NODE_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    // Leads = inbound-request reads (req.body / req.headers / update.message). The guard-gap (an ingress
    // handler with no signature/sender check) is what the hunt proves; a lone req read is not a finding.
    return scanSinkLeads(source, REQUEST_SHAPE_RE);
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
      const exported = new Set(nodeExportedNames(source));
      if (exported.size === 0) continue;
      const entries: Entry[] = functionUnits(source)
        .filter((u) => exported.has(u.name))
        .map((u) => ({
          name: u.name,
          line: u.line,
          body: u.body,
          isIngress: INGRESS_NAME_RE.test(u.name) || REQUEST_SHAPE_RE.test(u.body),
          hasAuthGuard: AUTH_GUARD_RE.test(u.body),
          reachesAction: ACTION_RE.test(u.body),
        }));

      // An ingress handler that reaches a privileged action with NO request-auth guard = the gap.
      const gaps = entries.filter((e) => e.isIngress && e.reachesAction && !e.hasAuthGuard).slice(0, 8);
      let fired = false;
      for (const gap of gaps) {
        if (fired) break;
        const marker = freshMarker();
        const driverRel = `.raeuber-noauth-${marker}.mjs`;
        sandbox.writeFile(driverRel, forgedIngressDriver(file, gap.name, marker));
        const run = sandbox.exec(`${NODE_RUN} ${driverRel} 2>&1`, 15_000);
        const out = run.stdout + run.stderr;
        if (!out.includes("NOAUTH_FIRED")) continue;
        exploits.push({
          attackClass: "missing-authentication",
          proof: "unauthenticated-action",
          file,
          line: gap.line,
          sink: `ingress(${gap.name})`,
          summary:
            `Exported inbound handler \`${gap.name}()\` processes a request and reaches a privileged action without verifying the request signature or authenticating the sender; a FORGED (unsigned) request carrying a marker action was accepted and processed (CWE-306/CWE-290).`,
          payload: `${gap.name}({ headers: {}, body: { action: "${marker}" } })  // no valid signature`,
          evidence:
            `driver drove \`${gap.name}()\` with a forged, unsigned request (marker ${marker}); the handler ` +
            `accepted and processed it — no authentication/signature check rejected it:\n` +
            out.slice(0, 700),
        });
        fired = true;
      }
    }
    return exploits;
  }
}

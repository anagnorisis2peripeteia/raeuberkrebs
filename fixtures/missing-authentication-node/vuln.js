// PLANTED VULNERABILITY (missing authentication on a webhook, CWE-306 / CWE-290): `handleWebhook`
// processes the inbound payload and performs its action WITHOUT verifying the HMAC signature, so a
// forged (unsigned) request drives it. `handleWebhookSafe` is the correct sibling — it verifies the
// signature first. The lane's canary drives an unsigned request carrying a marker action and observes
// `handleWebhook` accept and process it.

const crypto = require("crypto");

const WEBHOOK_SECRET = "s3cr3t-webhook-key";
let lastAction = null;

function expectedSignature(body) {
  return crypto.createHmac("sha256", WEBHOOK_SECRET).update(JSON.stringify(body)).digest("hex");
}

// The privileged action the webhook dispatches (a state-changing command).
function dispatchCommand(cmd) {
  lastAction = cmd;
  return { ok: true, executed: cmd };
}

// VULNERABLE: dispatches the payload's command with no signature check.
function handleWebhook(req) {
  const action = req && req.body && req.body.action;
  return dispatchCommand(action);
}

// REFERENCE: verifies the request signature before dispatching.
function handleWebhookSafe(req) {
  const sig = req && req.headers && req.headers["x-signature"];
  if (!sig || sig !== expectedSignature(req.body)) {
    throw new Error("invalid webhook signature");
  }
  return dispatchCommand(req.body && req.body.action);
}

module.exports.handleWebhook = handleWebhook;
module.exports.handleWebhookSafe = handleWebhookSafe;

// PLANTED VULNERABILITY (models openclaw's GHSA-j4mm-p864-vx7f, CWE-863): two exported entrypoints
// reach the SAME privileged effect `applySetting`, but the authorization guards diverge. `patchSetting`
// correctly gates it behind the ADMIN scope; `createSetting` reaches the identical effect behind only
// WRITE — so a WRITE-scoped caller escalates to the ADMIN-only reconfiguration. The lane's canary
// drives the weak twin under a WRITE-only credential and observes the ADMIN-gated sibling reject the
// same caller with an authorization error.

const store = { model: "default" };

class AuthzError extends Error {}

// The shared privileged effect both entrypoints reach.
function applySetting(patch) {
  if (patch && typeof patch.model === "string") store.model = patch.model;
  return { model: store.model };
}

// REFERENCE: the same effect, correctly gated behind ADMIN.
function patchSetting(ctx, patch) {
  if (!ctx || !Array.isArray(ctx.scopes) || !ctx.scopes.includes("admin")) {
    throw new AuthzError("patch requires admin scope");
  }
  return applySetting(patch);
}

// VULNERABLE: reaches the SAME applySetting effect behind only WRITE — the planted escalation.
function createSetting(ctx, patch) {
  if (!ctx || !Array.isArray(ctx.scopes) || !ctx.scopes.includes("write")) {
    throw new AuthzError("create requires write scope");
  }
  return applySetting(patch);
}

function getStore() {
  return { model: store.model };
}

module.exports.patchSetting = patchSetting;
module.exports.createSetting = createSetting;
module.exports.getStore = getStore;

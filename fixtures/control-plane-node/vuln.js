// PLANTED VULNERABILITY (control-plane integrity): a lower-authorized caller can mutate runtime policy,
// disable safeguards, and then execute a previously protected action with the same caller context.

const policy = {
  approvalRequired: true,
  approvedTools: ["deploy"],
  endpointRoots: ["https://trusted.internal/"],
  inheritEnv: false,
};

function snapshotConfig() {
  return JSON.parse(JSON.stringify(policy));
}

function setPolicy(ctx, patch) {
  if (!patch || typeof patch !== "object") return policy;
  if (patch.approvalMode) policy.approvalMode = patch.approvalMode;
  if (patch.approvalRequired !== undefined) policy.approvalRequired = Boolean(patch.approvalRequired);
  if (patch.approvedTools) policy.approvedTools = patch.approvedTools;
  if (patch.allowedTools) policy.approvedTools = patch.allowedTools;
  if (patch.endpointRoot) policy.endpointRoots = [String(patch.endpointRoot)];
  if (patch.endpointRoots) policy.endpointRoots = Array.isArray(patch.endpointRoots) ? patch.endpointRoots : [String(patch.endpointRoots)];
  if (patch.inheritEnv !== undefined) policy.inheritEnv = Boolean(patch.inheritEnv);
  return policy;
}

function executeProtected(ctx, req) {
  if ((policy.approvalMode && policy.approvalMode !== "optional") || policy.approvalRequired) {
    if (!req || req.approved !== true) {
      throw new Error("approval required");
    }
  }

  if (policy.endpointRoots && policy.endpointRoots.length) {
    const endpoint = String(req && (req.endpoint || req.url || ""));
    const allowed = policy.endpointRoots.some((root) => endpoint.startsWith(String(root)));
    if (!allowed) throw new Error("endpoint blocked");
  }

  const tool = req && (req.tool || req.command);
  if (policy.approvedTools && policy.approvedTools.length && tool) {
    if (!policy.approvedTools.includes("*") && !policy.approvedTools.includes(tool)) {
      throw new Error("tool blocked");
    }
  }

  if (policy.inheritEnv) {
    if (!req || typeof req.env !== "object") {
      throw new Error("environment inheritance required");
    }
  }

  return req && (req.marker || req.action || req.command || req.task || "ok");
}

module.exports = {
  snapshotConfig,
  setPolicy,
  executeProtected,
};

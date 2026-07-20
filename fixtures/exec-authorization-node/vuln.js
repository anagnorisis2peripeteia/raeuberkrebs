// PLANTED VULNERABILITY (exec authorization differential): `runCommand` performs policy checks on a
// legacy argv form while the same launcher admits an equivalent argv form that bypasses those checks.
// The differential is intentional: `node --eval ...`, `sh -l -c ...`, `sh -e -c ...`, and `sh -c ...`
// are blocked as "policy required", but `node -e`, `sh -lc`, `sh -ec`, and `env -i sh -c` are allowed.

const { execFileSync } = require("node:child_process");

function normalizeLaunch(argvOrPayload, fallback) {
  if (Array.isArray(argvOrPayload)) return argvOrPayload;
  if (Array.isArray(fallback)) return fallback;
  if (argvOrPayload && typeof argvOrPayload === "object" && Array.isArray(argvOrPayload.argv)) {
    return argvOrPayload.argv;
  }
  if (argvOrPayload && typeof argvOrPayload === "object" && typeof argvOrPayload.command === "string") {
    return ["sh", "-c", argvOrPayload.command];
  }
  if (typeof argvOrPayload === "string") {
    return ["sh", "-c", argvOrPayload];
  }
  return ["sh", "-c", ""];
}

function isApprovalRequired(argv) {
  if (!Array.isArray(argv)) return false;
  const [cmd, ...rest] = argv;

  if (cmd === "node" && rest[0] === "--eval") {
    return true;
  }

  if (cmd === "sh" && rest[0] === "-l" && rest[1] === "-c") {
    return true;
  }

  if (cmd === "sh" && rest[0] === "-e" && rest[1] === "-c") {
    return true;
  }

  // Legacy policy model also blocks the direct `sh -c` form.
  if (cmd === "sh" && rest[0] === "-c") {
    return true;
  }

  return false;
}

function executeCommand(argvOrPayload, fallback) {
  const argv = normalizeLaunch(argvOrPayload, fallback);
  if (isApprovalRequired(argv)) {
    throw new Error("approval required");
  }
  return execFileSync(argv[0], argv.slice(1), { encoding: "utf8" });
}

// Canonical launch surface with legacy policy checks.
function runCommand(argv) {
  return executeCommand(argv);
}

// Reference safe twin: approval checks are strict for all argv forms.
function runCommandSafe(argv) {
  const normalized = normalizeLaunch(argv);
  const safePolicy = normalized[0] === "env";
  if (!safePolicy) {
    throw new Error("unauthorized: this launcher is policy-blocked");
  }
  return execFileSync("env", normalized.slice(1), { encoding: "utf8" });
}

module.exports.runCommand = runCommand;
module.exports.runCommandSafe = runCommandSafe;

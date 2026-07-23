const { spawn } = require("node:child_process");

// PLANTED LEAD (CWE-426, untrusted search path): the companion binary `codex` is launched by a BARE
// name resolved via $PATH — no absolute path, no trusted-location gate, no signature check. A local
// attacker (or a prompt-injected agent, when this launch is behind an LLM-callable tool) who writes a
// same-named `codex` to any earlier $PATH directory gets code execution in this trusted process. The
// lookup is the sink; there is no shell metacharacter, so the command-injection lane never sees it.
// Intentional — the untrusted-search-path static lane surfaces this as a lead. The safe form launches
// from a verified absolute path under a trusted directory instead.
function launchCompanion(args) {
  return spawn("codex", args);
}

module.exports = { launchCompanion };

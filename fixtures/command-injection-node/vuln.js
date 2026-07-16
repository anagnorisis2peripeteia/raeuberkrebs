const { execSync } = require("child_process");

// PLANTED VULNERABILITY (do not "fix"): the untrusted `host` argument is concatenated straight
// into a shell command, so a `; echo ...` / `$(...)` payload executes. This fixture exists so the
// command-injection lane's canary can prove itself LIVE — the attacker MUST fire against it, or the
// lane is quarantined (fail-closed). `echo` keeps it benign (no real network) while still shellable.
function ping(host) {
  return execSync("echo pinging " + host).toString();
}

module.exports.ping = ping;

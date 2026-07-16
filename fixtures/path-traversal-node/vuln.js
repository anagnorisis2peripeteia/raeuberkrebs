const fs = require("fs");
const path = require("path");

// PLANTED VULNERABILITY (do not "fix"): `name` is joined onto a base dir with NO containment check,
// so a `../` payload escapes ./public and reads arbitrary files. Exists so the path-traversal lane's
// canary can prove itself LIVE by reading a decoy secret the attacker plants outside ./public.
function read(name) {
  return fs.readFileSync(path.join(__dirname, "public", name)).toString();
}

module.exports.read = read;

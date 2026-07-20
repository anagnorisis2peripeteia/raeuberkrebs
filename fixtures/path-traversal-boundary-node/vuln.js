const fs = require("fs");
const path = require("path");

// PLANTED VULNERABILITY: guard is path-based and only checks the lexical prefix. A caller-controlled
// `boundary-link/*` input bypasses that boundary via a symlink to parent scope (capability boundary
// bypass via filesystem aliasing).
const root = __dirname;
const safe = path.join(root, "boundary-safe.txt");
if (!fs.existsSync(safe)) {
  fs.writeFileSync(safe, "BOUNDARY_OK");
}

const boundaryLink = path.join(root, "boundary-link");
try {
  fs.symlinkSync(path.join(root, ".."), boundaryLink);
} catch {
  // best-effort, idempotent setup
}

function read(name) {
  const target = path.join(root, name);
  if (!target.startsWith(root + path.sep)) {
    throw new Error("denied");
  }
  return fs.readFileSync(target, "utf8");
}

module.exports.read = read;

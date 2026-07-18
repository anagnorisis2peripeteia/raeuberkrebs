// PLANTED VULNERABILITY (Zip Slip / archive path traversal, CWE-22): `extractEntries` writes each
// archive entry to `path.join(destDir, entry.name)` WITHOUT verifying the resolved path stays inside
// destDir — so an entry named `../x` escapes the extraction directory. `extractEntriesSafe` is the
// correct sibling (it resolves + containment-checks each entry). The lane's canary extracts a `../`
// entry into a sandbox target dir and observes the marker file land OUTSIDE it.

const fs = require("fs");
const path = require("path");

function extractEntries(entries, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  for (const entry of entries) {
    const dest = path.join(destDir, entry.name); // no containment -> `../` escapes destDir
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, entry.data);
  }
}

// REFERENCE: rejects any entry that resolves outside destDir.
function extractEntriesSafe(entries, destDir) {
  const root = path.resolve(destDir);
  fs.mkdirSync(root, { recursive: true });
  for (const entry of entries) {
    const dest = path.resolve(root, entry.name);
    if (dest !== root && !dest.startsWith(root + path.sep)) {
      throw new Error("blocked path traversal in archive entry: " + entry.name);
    }
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, entry.data);
  }
}

module.exports.extractEntries = extractEntries;
module.exports.extractEntriesSafe = extractEntriesSafe;

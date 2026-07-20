// PLANTED VULNERABILITY (second-order / stored taint, CWE-20): untrusted input passes through a light
// normalizer, is persisted, and later read back through a sibling entrypoint without a second validation
// pass. The marker is written into storage and returned on read, proving write->read flow.

const records = {};
let seq = 0;

function normalize(v) {
  return String(v ?? "").trim();
}

function writeRecord(ctx, payload) {
  const key = String(payload && (payload.key || payload.id || ++seq));
  records[key] = normalize(payload && payload.value);
  return { key, createdBy: ctx && ctx.identity };
}

function readRecord(ctx, key) {
  return records[key];
}

module.exports.writeRecord = writeRecord;
module.exports.readRecord = readRecord;

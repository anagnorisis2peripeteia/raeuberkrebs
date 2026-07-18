// PLANTED VULNERABILITY (ReDoS / catastrophic backtracking, CWE-1333 / CWE-400): `validate` tests
// caller input against `/^(a+)+$/` — a nested-quantifier regex. A short input like "aaaa…aaa!" (a run
// of 'a' followed by a non-matching '!') forces exponential backtracking and hangs the process.
// `validateSafe` uses the equivalent LINEAR regex and returns instantly on the same input. The lane's
// canary drives the crafted input and observes the hang.

function validate(input) {
  return /^(a+)+$/.test(input);
}

// REFERENCE: the linear-time equivalent — no nested quantifier, no catastrophic backtracking.
function validateSafe(input) {
  return /^a+$/.test(input);
}

module.exports.validate = validate;
module.exports.validateSafe = validateSafe;

// PLANTED VULNERABILITY (prototype pollution, CWE-1321): `deepMerge` recursively copies keys from an
// attacker-controlled source into a target WITHOUT filtering `__proto__` / `constructor` / `prototype`.
// A payload `{"__proto__":{"x":1}}` walks into `Object.prototype` and writes there, polluting every
// object in the process. `safeMerge` is the correct sibling (it skips the dangerous keys). The lane's
// canary drives a `__proto__` payload and observes a fresh `{}` inherit the injected property.

function deepMerge(target, src) {
  for (const key in src) {
    const val = src[key];
    if (val && typeof val === "object" && target[key] && typeof target[key] === "object") {
      deepMerge(target[key], val); // recurses through target["__proto__"] -> Object.prototype
    } else {
      target[key] = val;
    }
  }
  return target;
}

// REFERENCE: same merge, but refuses the prototype-walking keys.
function safeMerge(target, src) {
  for (const key in src) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    const val = src[key];
    if (val && typeof val === "object" && target[key] && typeof target[key] === "object") {
      safeMerge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

module.exports.deepMerge = deepMerge;
module.exports.safeMerge = safeMerge;

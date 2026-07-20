const yaml = {
  load(text) {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed.__yaml_exec === "string") {
      return Function(parsed.__yaml_exec)();
    }
    return parsed;
  },
};

// PLANTED VULNERABILITY (node-serialize style): attacker control reaches `_$$ND_FUNC$$_...` and is
// executed as code via a deserialization helper. This is intentionally unsafe and exists so the lane can
// prove itself live.
function unserialize(payload) {
  const parsed = JSON.parse(payload);
  if (typeof parsed?.__rce === "string" && parsed.__rce.startsWith("_$$ND_FUNC$$_function")) {
    return Function("return " + parsed.__rce)();
  }
  return parsed;
}

// PLANTED VULNERABILITY (yaml.load without safe schema): `yaml.load(...)` passes attacker input to a
// loader that evaluates attacker payload.
function loadYaml(payload) {
  return yaml.load(payload);
}

// PLANTED VULNERABILITY (prototype-pollution reviver): a reviver with unsafe prototype writes attacker
// keys into Object.prototype, so every object inherits the injected marker.
function parseWithReviver(payload) {
  return JSON.parse(payload, function (_key, value) {
    if (_key === "__proto__" && value && typeof value === "object") {
      Object.assign(Object.prototype, value);
    }
    return value;
  });
}

module.exports.unserialize = unserialize;
module.exports.loadYaml = loadYaml;
module.exports.parseWithReviver = parseWithReviver;

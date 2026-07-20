const vm = require("node:vm");

// Constant-arg control: fixed literals are safe-by-construction and should be ignored by this lane.
function safeEval() {
  return eval("1 + 1");
}

function runEval(code) {
  return eval(code);
}

function runFunction(body) {
  return new Function(body)();
}

function runVm(code) {
  return vm.runInThisContext(code);
}

module.exports = {
  safeEval,
  runEval,
  runFunction,
  runVm,
};

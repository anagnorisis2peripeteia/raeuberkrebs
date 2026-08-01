import { nodeDriverImport } from "./attacker.js";

// Shared entrypoint-driving primitive (the Phase-3 driver upgrade). Real npm APIs reach a sink through
// shapes the old direct-`await fn(arg)` driver could not: an ASYNC/callback sink (the effect fires
// after the call returns), a CLASS constructor + method, a payload carried in a CONFIG-OBJECT field,
// and methods that only run when handed a CALLBACK. This builds a driver that enumerates all of those
// for one export and one payload, supplies a benign callback, then SETTLES so async effects land. It
// does NOT itself decide "fired" — the caller observes a lane-specific side effect (e.g. a marker file
// the payload writes) AFTER the exec, host-side, so a driver crash can never hide a real fire.

/** Common option/field names real APIs carry the tainted value in (bounded to avoid blow-up). */
const FIELDS = [
  "ip", "host", "hostname", "address", "path", "file", "filename", "dir", "cmd", "command", "url",
  "input", "name", "target", "src", "source", "arg", "args", "value", "data", "query", "id",
];

/** Milliseconds to wait after driving, so an async/callback sink's effect (e.g. an `exec` in a
 *  callback) completes before the caller observes the marker. */
const SETTLE_MS = 1500;

/**
 * Build a driver that drives `exportName` from `moduleRel` with `payloadExpr` across every plausible
 * entrypoint shape and injection position, appends a benign callback, and settles. `payloadExpr` is a
 * JS expression (already a string literal or a builder) evaluating to the payload value. The driver is
 * defensive: global handlers swallow async rejections / uncaught throws from a mis-driven call so it
 * always reaches the settle, and every individual call is try/caught. The caller checks its own side
 * effect (marker file) after running this.
 */
export function driveEntrypointDriver(moduleRel: string, exportName: string, payloads: string[]): string {
  const mod = JSON.stringify("./" + moduleRel);
  const fn = JSON.stringify(exportName);
  return `
process.on("unhandledRejection", () => {});
process.on("uncaughtException", () => {});
${nodeDriverImport(mod)}
const target = (m && m[${fn}]) || (m && m.default && (m.default[${fn}] || m.default));
if (target == null) { process.exit(0); }
const PAYLOADS = ${JSON.stringify(payloads)};
const FIELDS = ${JSON.stringify(FIELDS)};
// Capture what each driven call PRODUCES — sync return, resolved promise, and callback args — so a
// lane whose fire signal is a RETURNED value (path-traversal's decoy content, a sqli marker row) can
// observe it, not just lanes whose signal is an external side effect (command-injection's marker file).
const CAP = [];
function observe(v) {
  try { CAP.push(typeof v === "string" ? v : (v && v.stdout ? String(v.stdout) : JSON.stringify(v))); }
  catch { CAP.push(String(v)); }
  if (CAP.length > 500) CAP.shift();
}
const cb = (...args) => { for (const a of args) observe(a); };
function tryCall(fn, args) {
  try {
    const r = fn(...args);
    if (r && typeof r.then === "function") r.then(observe, observe);
    else observe(r);
  } catch (e) { observe(e && e.message); }
}
// Drive one callable with the payload in each position: positional (with & without a callback) and as
// each config-object field (with a callback).
function drive(fn, P) {
  tryCall(fn, [P, cb]);
  tryCall(fn, [P]);
  for (const f of FIELDS) tryCall(fn, [{ [f]: P }, cb]);
}
function driveTarget(t, P) {
  if (typeof t === "function") {
    drive(t, P);
    // Class-constructor + method: construct with the payload / an empty object / each config field,
    // then drive every own+prototype method of the instance.
    for (const ctorArgs of [[P], [{}], ...FIELDS.map((f) => [{ [f]: P }])]) {
      try {
        const inst = new t(...ctorArgs);
        const proto = Object.getPrototypeOf(inst) || {};
        const methods = [...new Set(Object.getOwnPropertyNames(proto).concat(Object.keys(inst)))]
          .filter((mn) => mn !== "constructor" && typeof inst[mn] === "function");
        for (const mn of methods) drive(inst[mn].bind(inst), P);
      } catch {}
    }
  }
  // Object of methods (e.g. \`module.exports = { list, dump, ... }\`).
  if (t && typeof t === "object") {
    for (const k of Object.keys(t)) if (typeof t[k] === "function") drive(t[k].bind(t), P);
  }
}
for (const P of PAYLOADS) driveTarget(target, P);
await new Promise((r) => setTimeout(r, ${SETTLE_MS}));
process.stdout.write("RK_CAP\\u0001" + CAP.join("\\u0001").slice(0, 20000));
`.trim();
}

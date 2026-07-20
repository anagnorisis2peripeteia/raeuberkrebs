function renderTemplate(template, context) {
  const raw = String(template ?? "");
  const ctx = context || {};
  const engine = {
    render: (tpl, ctx2) =>
      tpl.replace(/\{\{\s*([A-Za-z_$][\w$]*)\s*\}\}/g, (_match, name) => {
        const v = ctx2[name];
        return v == null ? "" : String(v);
      }),
  };
  return engine.render(raw, ctx);
}

function logLine(message) {
  console.info("audit:", String(message));
  return "ok";
}

function toCsv(value) {
  return ["id", String(value)].join(",");
}

function setLocation(a, b, c) {
  const res = a && typeof a.setHeader === "function" ? a : b && typeof b.setHeader === "function" ? b : null;
  const value = res === a ? b : c;
  return res ? res.setHeader("Location", String(value)) : "ok";
}

module.exports = {
  renderTemplate,
  logLine,
  toCsv,
  setLocation,
};
 

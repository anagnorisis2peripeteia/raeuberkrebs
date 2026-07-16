// PLANTED VULNERABILITY (models openclaw's google-meet `csvCell`): RFC-4180 quote-escaping only —
// it wraps a cell containing `" , \n`, but does NO formula-prefix neutralization. An untrusted cell
// like `=cmd|'/c calc'!A1` contains none of those trigger chars, so it reaches the CSV verbatim and
// executes when the file is opened in a spreadsheet. The lane's canary drives this to prove itself live.
function csvCell(value) {
  const text = value == null ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function toCsv(rows) {
  return rows.map((row) => row.map(csvCell).join(",")).join("\n");
}

module.exports.toCsv = toCsv;

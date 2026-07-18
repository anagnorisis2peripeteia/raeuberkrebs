import Foundation

// PLANTED VULNERABILITY (do not "fix"): RFC-4180 quote-escaping only, with NO formula-prefix guard —
// a cell whose value begins with `= + - @` is emitted verbatim and executes when the CSV is opened in
// Excel/Sheets. Models the real openclaw google-meet `csvCell`. Exists so the Swift CSV/formula-
// injection lane's canary can prove itself LIVE by driving a `=<marker>` value that survives into the
// output un-neutralized. Runs on the macOS host.
func csvCell(_ value: String) -> String {
    var out = value
    if out.contains(",") || out.contains("\"") || out.contains("\n") {
        out = "\"" + out.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
    return out + ",count"
}

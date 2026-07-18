import Foundation

// PLANTED VULNERABILITY (do not "fix"): a catastrophic-backtracking regex — the shell-quote parser
// shape — applied to input. `(?:\\.|[^'])*` is ambiguous because `[^']` includes the backslash, which
// also begins `\\.`, so a run of backslashes with no closing quote backtracks exponentially. Exists so
// the Swift ReDoS lane's canary can prove itself LIVE by timing the compiled pattern against a crafted
// `$'`+backslashes input. (This models the real steipete/CodexBar T3Chat cURL-header parser.)
func parseHeaders(_ raw: String) -> Int {
    let pattern = #"(?:\$'((?:\\.|[^'])*)'|'([^']*)'|"((?:\\.|[^"])*)"|(\S+))"#
    guard let re = try? NSRegularExpression(pattern: pattern) else { return 0 }
    let range = NSRange(raw.startIndex..<raw.endIndex, in: raw)
    return re.matches(in: raw, options: [], range: range).count
}

import Foundation

// PLANTED VULNERABILITY (do not "fix"): `name` is concatenated onto the ./public base dir with NO
// containment check, so a `../` payload escapes ./public and reads arbitrary files. Exists so the
// Swift path-traversal lane's canary can prove itself LIVE by reading a decoy secret the attacker
// plants outside ./public. Runs on the macOS host (local sandbox).
func readPublic(_ name: String) -> String {
    let base = FileManager.default.currentDirectoryPath + "/public"
    let path = base + "/" + name
    return (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
}

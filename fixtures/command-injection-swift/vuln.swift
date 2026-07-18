import Foundation

// PLANTED VULNERABILITY (do not "fix"): the untrusted `host` argument is interpolated straight into a
// `/bin/sh -c` command string, so a `; echo …` / `$(…)` / backtick payload executes. This fixture
// exists so the Swift command-injection lane's canary can prove itself LIVE — the attacker MUST fire
// against it, or the lane is quarantined (fail-closed), exactly like the Node/`.NET` fixtures. `echo`
// keeps it benign (no real effect) while still shellable.
func pingHost(_ host: String) -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", "echo pinging \(host)"]
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    try? process.run()
    process.waitUntilExit()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8) ?? ""
}

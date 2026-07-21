import Foundation

// Planted-vulnerable command-approval gate (the exec canary). It BELIEVES a command is safe unless
// it starts with a tiny denylist — so a plain `echo`, an `sh -c ...`, or a bare executable path is
// auto-approved and, when run, executes. Its BELIEF (safe) diverges from GROUND TRUTH (it ran). The
// lane's exec-marker strategy must catch this to prove itself LIVE.
enum NaiveCommandApprover {
    static func isCommandSafe(_ command: String) -> Bool {
        let banned = ["rm ", "curl ", "dd ", "mkfs"]
        for b in banned where command.contains(b) { return false }
        return true // naive: everything else is "safe" — including a marker command / marker executable
    }
}

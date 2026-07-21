using System;

namespace RkFixture
{
    // PLANTED VULNERABILITY (do not "fix"): a command-approval control that auto-approves any
    // `command <x>` invocation — a miniature of the real openclaw `command`-builtin carrier bypass
    // (GHSA-ghpx). The control BELIEVES the `command ` prefix is a safe no-op, but `command echo X`
    // actually RUNS echo. This fixture exists so the C# command-approval differential-oracle lane's
    // canary can prove itself LIVE: the lane MUST report a divergence here (believed-safe AND the
    // marker executed), or the lane is quarantined (fail-closed). `echo` keeps it benign.
    public static class Approval
    {
        public static bool IsCommandSafe(string cmd)
        {
            if (cmd == null) return false;
            // FLAW: the `command` builtin prefix is whitelisted as harmless, but it is a CARRIER —
            // `command echo <marker>` runs echo. The oracle drives exactly this divergence.
            if (cmd.StartsWith("command ")) return true;
            // Everything else is only "safe" if it is a literal no-op — so the plain `echo <marker>`
            // corpus item is (correctly) judged UNSAFE and must NOT be reported (no false positive).
            return cmd == "true" || cmd == ":";
        }
    }
}

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RkFixture
{
    // PLANTED VULNERABILITY (do not "fix"): the untrusted `host` argument is concatenated straight
    // into a shell command line, so a `; echo ...` / `&& echo ...` / `$(...)` payload executes. This
    // fixture exists so the .NET command-injection lane's canary can prove itself LIVE — the attacker
    // MUST fire against it, or the lane is quarantined (fail-closed). `echo` keeps it benign (no real
    // network) while still shellable. OS-aware so it fires on the Mac/Linux local sandbox and on a
    // Windows box alike.
    public static class Pinger
    {
        public static string Ping(string host)
        {
            bool win = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            var psi = new ProcessStartInfo
            {
                FileName = win ? "cmd.exe" : "/bin/sh",
                Arguments = win ? ("/c echo pinging " + host) : ("-c \"echo pinging " + host + "\""),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            var p = Process.Start(psi);
            string outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return outp;
        }
    }
}

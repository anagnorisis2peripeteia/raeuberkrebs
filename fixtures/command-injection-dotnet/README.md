# command-injection-dotnet fixture

Planted-vulnerable C# used by the **.NET** command-injection lane's liveness canary. `Pinger.Ping`
concatenates its untrusted `host` argument into a shell command line. **Do not "fix" it** — the lane
proves itself LIVE by firing a benign `echo <marker>` payload through this sink; if it can't, the
lane is quarantined (fail-closed), exactly like the Node fixtures.

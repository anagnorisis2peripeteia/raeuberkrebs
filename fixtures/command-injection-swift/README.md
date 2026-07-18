# command-injection-swift fixture

Planted-vulnerable Swift used by the **Swift** command-injection lane's liveness canary. `pingHost`
interpolates its untrusted `host` argument into a `/bin/sh -c` command string. **Do not "fix" it** —
the lane proves itself LIVE by firing a benign `echo <marker>` payload through this sink; if it
can't, the lane is quarantined (fail-closed), exactly like the Node/`.NET` fixtures. Swift compiles
and runs natively on the macOS host (the local sandbox); AppKit-linked app code does not
cross-compile to the Linux crabbox box, so the Swift lane proves here on macOS.

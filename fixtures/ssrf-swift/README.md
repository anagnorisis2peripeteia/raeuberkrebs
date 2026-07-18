# ssrf-swift fixture

Planted-vulnerable Swift used by the **Swift** SSRF lane's liveness canary. `fetchURL` fetches the raw
URL argument, so an attacker who controls the argument controls the request host. **Do not "fix" it**
— the lane proves itself LIVE by driving a `127.0.0.1:<ephemeral>` loopback URL carrying a per-run
marker and observing the out-of-band request at an in-sandbox TCP listener (`oob-request`). Zero
external network. Runs on the macOS host (local sandbox).

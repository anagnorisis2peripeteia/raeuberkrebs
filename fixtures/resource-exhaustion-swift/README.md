# resource-exhaustion-swift fixture

Planted-vulnerable Swift used by the **Swift** ReDoS lane's liveness canary. `parseHeaders` applies a
catastrophic-backtracking regex (`(?:\\.|[^'])*` — `[^']` overlaps `\\.` on a backslash) to input.
**Do not "fix" it** — the lane proves itself LIVE by extracting the pattern and timing it against a
crafted `$'`+backslashes input (the compiled regex hangs while a benign input is instant). Models the
real steipete/CodexBar `T3ChatUsageFetcher.headerFields` cURL parser. Runs on the macOS host.

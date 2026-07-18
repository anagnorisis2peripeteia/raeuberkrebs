# path-traversal-swift fixture

Planted-vulnerable Swift used by the **Swift** path-traversal lane's liveness canary. `readPublic`
concatenates its untrusted `name` onto the `./public` base dir with no containment check, so a `../`
payload escapes and reads arbitrary files. **Do not "fix" it** — the lane proves itself LIVE by
planting a decoy secret at the sandbox root (its content is a marker distinct from its filename) and
reading it back via `../`. The `public/` subdir must exist so `public/../decoy` resolves at the OS
level. Runs on the macOS host (local sandbox).

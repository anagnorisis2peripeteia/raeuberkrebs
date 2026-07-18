# csv-injection-swift fixture

Planted-vulnerable Swift used by the **Swift** CSV/formula-injection lane's liveness canary. `csvCell`
does RFC-4180 quote-escaping but no formula-prefix guard, so a value beginning with `= + - @` is
emitted verbatim (models the real openclaw google-meet `csvCell`). **Do not "fix" it** — the lane
proves itself LIVE by driving a `=<marker>` value that survives into the output as a cell still
beginning with `=` (`formula-unescaped`). Runs on the macOS host.

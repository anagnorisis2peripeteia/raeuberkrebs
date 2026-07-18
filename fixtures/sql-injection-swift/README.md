# sql-injection-swift fixture

Planted-vulnerable Swift used by the **Swift** SQL-injection lane's liveness canary. `lookup`
interpolates its untrusted `name` straight into a SQL WHERE clause. **Do not "fix" it** — the lane
proves itself LIVE by driving an `' OR '1'='1` payload that bypasses the WHERE and returns a row a
benign lookup does not (differential `secret-exfiltrated` proof). SQLite3 is a macOS system module,
so it compiles with `swiftc` directly. Runs on the macOS host.

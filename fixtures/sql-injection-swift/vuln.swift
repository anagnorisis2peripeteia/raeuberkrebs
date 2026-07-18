import Foundation
import SQLite3

// PLANTED VULNERABILITY (do not "fix"): the untrusted `name` argument is interpolated straight into a
// SQL WHERE clause, so an `' OR '1'='1`-style payload bypasses it and returns rows it should not.
// Exists so the Swift SQL-injection lane's canary can prove itself LIVE by driving an injection that
// leaks a row a benign lookup does not. Runs on the macOS host (SQLite3 is a system module).
func lookup(_ name: String) -> String {
    var db: OpaquePointer?
    sqlite3_open(":memory:", &db)
    sqlite3_exec(db, "CREATE TABLE t(name TEXT, val TEXT)", nil, nil, nil)
    sqlite3_exec(db, "INSERT INTO t VALUES('public','ok')", nil, nil, nil)
    sqlite3_exec(db, "INSERT INTO t VALUES('secret','RAEUBER_sqli_row')", nil, nil, nil)
    let sql = "SELECT val FROM t WHERE name = '\(name)'"
    var stmt: OpaquePointer?
    var out = ""
    if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let c = sqlite3_column_text(stmt, 0) { out += String(cString: c) + ";" }
        }
    }
    sqlite3_finalize(stmt)
    sqlite3_close(db)
    return out
}

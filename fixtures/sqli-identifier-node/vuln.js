// PLANTED VULNERABILITY (models openclaw's sqlite-index-schema `DROP INDEX main.${index.name}` and
// task-registry `CREATE TEMP TABLE ${tempTableName}`): a SQL identifier is interpolated straight into
// a statement passed to db.exec with NO identifier-quoting guard. If `table` is attacker-controlled,
// it is SQL injection (a `"; DROP TABLE ...; --` style identifier escapes). The safe siblings wrap the
// identifier in quoteSqliteIdentifier(...); this one does not. The lane's canary drives this live.
function dropTable(db, table) {
  return db.exec(`DROP TABLE ${table}`);
}

module.exports.dropTable = dropTable;

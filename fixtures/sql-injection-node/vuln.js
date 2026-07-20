const { DatabaseSync } = require("node:sqlite");

const db = new DatabaseSync(":memory:");
db.exec("CREATE TABLE users(name TEXT, secret TEXT)");
db.exec("INSERT INTO users VALUES('public', 'ok')");
db.exec("INSERT INTO users VALUES('admin', 'RAEUBER_FIXTURE_SECRET')");

function findUser(name) {
  const query = "SELECT secret FROM users WHERE name = '" + name + "'";
  const rows = db.prepare(query).all();
  return rows.map((row) => row.secret).join(",");
}

module.exports = { findUser };

// PLANTED VULNERABILITY (IDOR / broken object-level authorization, CWE-639): `getDoc` resolves a
// document from a caller-supplied id and returns it WITHOUT checking that the caller owns it — so any
// identity can read any other identity's document by supplying its id. `getDocSafe` is the correct
// sibling (it enforces ownership). The lane's canary creates a doc as "alice", then reads it back as
// "bob" through `getDoc` and observes alice's marker leak.

const docs = {};
let seq = 0;

class AuthzError extends Error {}

function createDoc(ctx, body) {
  const id = "doc-" + ++seq;
  docs[id] = { owner: ctx && ctx.identity, body };
  return { id };
}

// VULNERABLE: returns the document by id with no ownership check.
function getDoc(ctx, id) {
  const d = docs[id];
  if (!d) throw new Error("not found");
  return { id, body: d.body };
}

// REFERENCE: the same lookup, correctly gated on ownership.
function getDocSafe(ctx, id) {
  const d = docs[id];
  if (!d) throw new Error("not found");
  if (d.owner !== (ctx && ctx.identity)) {
    throw new AuthzError("forbidden: caller is not the owner");
  }
  return { id, body: d.body };
}

module.exports.createDoc = createDoc;
module.exports.getDoc = getDoc;
module.exports.getDocSafe = getDocSafe;

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authzFailOpenDotnet } from "./dotnet-oracle.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * The C# differential-authorization lane — a drive-and-prove authz fail-open oracle. Where the Node
 * BrokenAccessControlAttacker pairs two entrypoints under duck-typed contexts, statically-typed C#
 * has no such generic context shape; the tractable, policy-free invariant is instead: a role/
 * permission gate MUST deny a NULL-AUTHORITY principal (no roles, no claims). This lane discovers a
 * `bool IsAuthorized(ClaimsPrincipal)`-shaped gate, compiles it with a driver that constructs the
 * empty principal, and reports a divergence when the gate ADMITS the role-less caller (CWE-862/863).
 *
 * The planted fixture (`fixtures/authz-fail-open-dotnet/Authorizer.cs`) fails open on an empty role
 * set so the lane proves itself LIVE. It correctly does NOT fire on a sound gate
 * (`GetUserRoles().Any(r => allowed.Contains(r))` denies the empty set) — so e.g. microsoft/
 * mcp-gateway's `BuiltinToolAuthorizer` would not be flagged. Copy-me TEMPLATE: point `handles` at a
 * target's authorizer file (see PLAYBOOK.md).
 */
export const AuthzFailOpenDotnetAttacker = authzFailOpenDotnet({
  attackClass: "broken-access-control",
  canaryFixtureDir: resolve(HERE, "..", "..", "fixtures", "authz-fail-open-dotnet"),
  beliefLabel: "role/permission gate",
  handles: (file) => file === "Authorizer.cs",
  // methodName defaults to the common authz verbs (IsAuthorized/Authorize/HasPermission/Can…).
});

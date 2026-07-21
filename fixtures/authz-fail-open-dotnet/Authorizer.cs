using System;
using System.Linq;
using System.Security.Claims;

namespace RkFixture
{
    // PLANTED VULNERABILITY (do not "fix"): a role gate that FAILS OPEN. `IsAuthorized` is meant to
    // admit only callers holding an allowed role, but it treats a caller with NO roles as trusted
    // ("internal/system") and returns true. A correct role gate MUST deny the null-authority
    // principal — compare the sound shape `roles.Any(r => Allowed.Contains(r))`, which denies the
    // empty set. This fixture exists so the C# authz fail-open oracle lane's canary can prove itself
    // LIVE: the lane constructs an empty ClaimsPrincipal, calls the gate, and MUST observe it admit
    // the role-less caller, or the lane is quarantined (fail-closed).
    public static class Authorizer
    {
        static readonly string[] Allowed = new[] { "admin" };

        public static bool IsAuthorized(ClaimsPrincipal principal)
        {
            var roles = principal.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            // FLAW: a role-less caller is assumed to be an internal/system principal and allowed.
            // The oracle's null-authority principal (`new ClaimsPrincipal(new ClaimsIdentity())`)
            // carries zero role claims, so this admits it — a fail-open authorization bypass.
            if (roles.Count == 0) return true;

            return roles.Any(r => Allowed.Contains(r));
        }
    }
}

// PLANTED vulnerability for the SSRF trust-boundary differential canary.
// `fetchFromTrustBoundary` gates on a naive, protocol-tolerant allow-list check, then
// reuses attacker-controlled URL material for the outbound request and follows redirects.
// This intentionally permits protocol-relative, backslash-normalized, and userinfo forms to pass
// validation, and secret headers can be forwarded after redirect to another local origin.
const TRUST_HEADER = "x-raeuber-secret";

function normalize(raw) {
  return String(raw || "").replace(/\\/g, "/").trim();
}

function toFetchUrl(raw) {
  const norm = normalize(raw);
  if (norm.startsWith("//")) return "http:" + norm;
  return norm.startsWith("http://") || norm.startsWith("https://") ? norm : "http://" + norm;
}

function isAllowed(raw) {
  const norm = normalize(raw);
  return /^(?:[a-z][a-z0-9+.-]*:)?\/\/(?:[^/]*@)?127\.0\.0\.1:\d+\/api\//i.test(norm);
}

function tokenFromUrl(raw) {
  try {
    const req = new URL(toFetchUrl(raw));
    return req.searchParams.get("token") || "boundary";
  } catch {
    return "boundary";
  }
}

function fetchFromTrustBoundary(rawUrl) {
  if (!isAllowed(rawUrl)) {
    throw new Error("target not allowed");
  }

  const token = tokenFromUrl(rawUrl);
  return fetch(toFetchUrl(rawUrl), {
    redirect: "follow",
    headers: { [TRUST_HEADER]: `SSRF_${token}` },
  }).then((r) => r.text());
}

module.exports.fetchFromTrustBoundary = fetchFromTrustBoundary;

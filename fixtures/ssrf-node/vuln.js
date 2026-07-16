// Planted-vulnerable fixture for the SSRF lane's liveness canary.
// `fetchUrl` fetches an untrusted URL with no allowlist / no host validation — a classic SSRF sink.
// The canary proves the lane live by driving `url` at a loopback listener it controls.
function fetchUrl(url) {
  return fetch(url).then((r) => r.text());
}
module.exports.fetchUrl = fetchUrl;

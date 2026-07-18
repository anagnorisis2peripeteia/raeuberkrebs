import Foundation

// PLANTED VULNERABILITY (do not "fix"): fetches the raw URL argument, so an attacker who controls the
// argument controls the request host (SSRF). Exists so the Swift SSRF lane's canary can prove itself
// LIVE by driving a 127.0.0.1 loopback URL and observing the out-of-band request. Runs on the macOS
// host (local sandbox).
func fetchURL(_ u: String) -> String {
    guard let url = URL(string: u) else { return "" }
    let sema = DispatchSemaphore(value: 0)
    var out = ""
    URLSession.shared.dataTask(with: url) { data, _, _ in
        if let data = data { out = String(data: data, encoding: .utf8) ?? "" }
        sema.signal()
    }.resume()
    _ = sema.wait(timeout: .now() + 3)
    return out
}

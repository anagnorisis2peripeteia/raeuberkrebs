import Foundation

// Planted-vulnerable confinement DECISION (the canary for the Swift differential-oracle lane).
//
// It BELIEVES a path is confined to `base` using a lexical `hasPrefix` check on the RAW joined
// string — it never canonicalizes symlinks or collapses `..`. A `../` payload, or a path through an
// in-base symlink that points outside, escapes `base` yet is approved. Its BELIEF (approved) diverges
// from GROUND TRUTH (the write lands outside `base`). The lane must report this divergence to prove
// itself LIVE — a lane that cannot catch its own planted flaw is quarantined, never a silent pass.
enum NaiveConfiner {
    static func resolvePath(_ path: String) -> URL? {
        let base = FileManager.default.currentDirectoryPath + "/base"
        let joined = base + "/" + path
        guard joined.hasPrefix(base) else { return nil } // naive: no symlink/`..` canonicalization
        return URL(fileURLWithPath: joined)
    }
}

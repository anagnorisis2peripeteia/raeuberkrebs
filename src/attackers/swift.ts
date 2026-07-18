// Shared primitives for the Swift attacker lanes. The Node lanes drive an entrypoint by dynamically
// `import()`-ing the changed file with zero build; Swift is compiled, so a Swift lane instead parses
// the changed source for a function whose first parameter is a `String` (the injectable position),
// compiles that one file together with a generated `main.swift` driver into an isolated executable,
// then runs the driver once per payload. A file that needs the rest of its package to compile (it
// `import`s CodexBarCore / AppKit / another module) simply won't build in isolation — an honest miss
// (no finding), never a false pass. Swift runs NATIVELY on macOS (the local sandbox); AppKit-linked
// app code does not cross-compile to the Linux crabbox box, so the Swift lanes prove on the macOS
// host (the `.NET` lane already established a non-Node compiled path).

/** Swift source files a Swift lane can drive. */
export const SWIFT_SOURCE_RE = /\.swift$/;

export interface SwiftFunction {
  name: string;
  /** External argument label of the FIRST parameter: `"_"` = call with no label, else the label
   *  token that must precede the argument at the call site (Swift requires it). */
  firstLabel: string;
  /** Nearest enclosing `class`/`struct`/`enum`/`extension`/`actor`, or null for a free (top-level)
   *  function. */
  enclosingType: string | null;
  isStatic: boolean;
}

/** Enclosing type of a source offset: the nearest preceding `class|struct|enum|extension|actor Name`
 *  (not `class func`, whose name token is `func`). Null ⇒ a free/top-level function. */
function enclosingTypeAt(source: string, index: number): string | null {
  const before = source.slice(0, index);
  const matches = [...before.matchAll(/\b(?:class|struct|enum|extension|actor)\s+([A-Za-z_]\w*)/g)];
  for (let i = matches.length - 1; i >= 0; i--) {
    const name = matches[i][1];
    if (name !== "func") return name; // skip a `class func` false match
  }
  return null;
}

/**
 * Functions whose FIRST parameter is a `String` — the canonical injectable position, mirroring the
 * Node/`.NET` lanes' "drive the first argument". Same-module compilation (the target compiled
 * together with the driver) sees `internal` and `public` functions, so both are drivable;
 * `private`/`fileprivate` are excluded (invisible across files even within one module). Regex-level
 * (no SwiftSyntax dependency): good enough for helper/command-runner entrypoints, and honest about
 * ones hidden behind non-trivial initializers or `async`/generic constraints.
 */
export function swiftDrivableFunctions(source: string): SwiftFunction[] {
  const fns: SwiftFunction[] = [];
  // group1 = the modifier run right before `func`; group2 = name; group3 = optional first token
  // (external label or `_`); group4 = the internal parameter name (or, when group3 is absent, the
  // single name that is BOTH the label and the internal name).
  const re =
    /(?:^|\n)[ \t]*((?:(?:public|private|internal|fileprivate|open|static|class|final|override|mutating|nonisolated|@\w+)[ \t]+)*)func[ \t]+([A-Za-z_]\w*)[ \t]*(?:<[^>]*>)?[ \t]*\(\s*(?:([A-Za-z_]\w*|_)[ \t]+)?([A-Za-z_]\w*)[ \t]*:[ \t]*(?:inout[ \t]+)?String\b/g;
  const seen = new Set<string>();
  for (const m of source.matchAll(re)) {
    const mods = m[1] ?? "";
    if (/\b(?:private|fileprivate)\b/.test(mods)) continue; // not visible to the driver file
    const name = m[2];
    const firstLabel = m[3] === undefined ? m[4] : m[3]; // `_` stays `_` (no label at the call site)
    const enclosingType = enclosingTypeAt(source, m.index ?? 0);
    const isStatic = /\b(?:static|class)\b/.test(mods);
    // De-dup an overload set by type+name: driven once via its first string-first-arg signature.
    const key = `${enclosingType ?? ""}.${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    fns.push({ name, firstLabel, enclosingType, isStatic });
  }
  return fns;
}

/** The call expression that invokes `fn` with `argVar`, honouring Swift's argument-label rules and
 *  static-vs-instance dispatch. An instance method is called on a zero-arg `Type()` — a type needing
 *  a non-trivial initializer just won't compile/run (an honest miss), like the `.NET` lane's
 *  parameterless-ctor assumption. */
export function swiftCallExpr(fn: SwiftFunction, argVar: string): string {
  const arg = fn.firstLabel === "_" ? argVar : `${fn.firstLabel}: ${argVar}`;
  if (fn.enclosingType === null) return `${fn.name}(${arg})`;
  if (fn.isStatic) return `${fn.enclosingType}.${fn.name}(${arg})`;
  return `${fn.enclosingType}().${fn.name}(${arg})`;
}

/**
 * A `main.swift` (Swift requires top-level executable code to live in `main.swift`) that reads the
 * payload from argv, invokes the entrypoint, and prints whatever it returns — so a marker echoed by
 * an exercised shell sink is observable. The `.map { "\($0)" } ?? ""` renders ANY return type
 * (including `Void`) to a string, and `try?` swallows a `throws` entrypoint's error; the payload
 * arrives as argv (not baked in), so ONE compile serves every payload.
 */
export function swiftDriverMain(fn: SwiftFunction): string {
  return `import Foundation

let __rk_payload = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
let __rk_out = (try? ${swiftCallExpr(fn, "__rk_payload")}).map { "\\(String(describing: $0))" } ?? ""
print(__rk_out, terminator: "")
`;
}

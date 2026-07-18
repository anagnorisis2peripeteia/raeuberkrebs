// Shared primitives for the .NET (C#) attacker lanes. The Node lanes drive an entrypoint by
// dynamically `import()`-ing the changed file and calling an exported function with zero build. C#
// is compiled, so a .NET lane instead: parses the changed source for a public method whose first
// parameter is a string (the injectable position), compiles that one file together with a generated
// driver into an ISOLATED single-file console project, then runs the driver once per payload. A file
// that needs the rest of its project to compile simply won't build in isolation — an honest miss
// (no finding), never a false pass.

/** C# source files a .NET lane can drive. Includes code-behind (`*.xaml.cs`) — it ends in `.cs`. */
export const DOTNET_SOURCE_RE = /\.cs$/;

/** Env prefix that silences dotnet's banners/telemetry (so they can't pollute marker evidence) and
 *  keeps all CLI/NuGet state inside the throwaway sandbox working dir. Prefix for `sandbox.exec`. */
export const DOTNET_ENV =
  "DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_CLI_HOME=. ";

/** Target framework the generated driver project builds against. Both provisioned boxes ship SDK 10,
 *  whose default TFM is `net10.0` with a bundled runtime pack (so the build restores offline).
 *  Override via `RAEUBER_DOTNET_TFM` on a box with a different SDK major. */
export function dotnetTfm(): string {
  return process.env.RAEUBER_DOTNET_TFM ?? "net10.0";
}

export interface CsharpMethod {
  name: string;
  className: string;
  namespace: string | null;
  isStatic: boolean;
}

/** Namespace of a C# source (first block or file-scoped `namespace`), or null (global namespace). */
export function csharpNamespace(source: string): string | null {
  const m = source.match(/\bnamespace\s+([A-Za-z_][\w.]*)/);
  return m ? m[1] : null;
}

/**
 * Public methods whose FIRST parameter is a `string` — the canonical injectable position, mirroring
 * the Node lane's "drive the first argument". For each, resolve the enclosing type (nearest preceding
 * `class`/`record`/`struct`) and whether the method is static. This is regex-level (no Roslyn
 * dependency): good enough to drive helper/utility entrypoints, and honest about missing ones hidden
 * behind dependency-injected or non-trivial constructors.
 */
export function csharpDrivableMethods(source: string): CsharpMethod[] {
  const ns = csharpNamespace(source);
  const methods: CsharpMethod[] = [];
  const re =
    /\bpublic\s+((?:static\s+|async\s+|virtual\s+|override\s+|sealed\s+)*)[A-Za-z_][\w<>\[\]\.,\s]*?\s+([A-Za-z_]\w*)\s*\(\s*string\s+[A-Za-z_]\w*/g;
  const keywords = new Set(["if", "while", "for", "foreach", "switch", "catch", "using", "lock", "return"]);
  for (const m of source.matchAll(re)) {
    const mods = m[1] ?? "";
    const name = m[2];
    if (keywords.has(name)) continue;
    const idx = m.index ?? 0;
    const before = source.slice(0, idx);
    const classMatches = [...before.matchAll(/\b(?:class|record|struct)\s+([A-Za-z_]\w*)/g)];
    if (classMatches.length === 0) continue;
    const className = classMatches[classMatches.length - 1][1];
    methods.push({ name, className, namespace: ns, isStatic: /\bstatic\b/.test(mods) });
  }
  // De-dup by type+name: an overload set is driven once via its first string-first-arg signature.
  const seen = new Set<string>();
  return methods.filter((x) => {
    const k = `${x.className}.${x.name}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** The generated driver's csproj: a standalone console exe with no package deps (offline restore).
 *  `StartupObject` pins the entrypoint to the driver so a target file that also has a `Main` (or
 *  top-level statements) doesn't create an ambiguous-entrypoint build error for the common case. */
export function dotnetDriverCsproj(assemblyName: string): string {
  return `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>${dotnetTfm()}</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>disable</Nullable>
    <AssemblyName>${assemblyName}</AssemblyName>
    <StartupObject>__RaeuberDriver</StartupObject>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <LangVersion>latest</LangVersion>
  </PropertyGroup>
</Project>`;
}

/**
 * A Program.cs that invokes `<Namespace>.<Class>.<Method>(args[0])` (static) or
 * `new <Class>().<Method>(args[0])` (instance) and prints the returned value / caught error message,
 * so a marker echoed by an exercised shell sink is observable. The payload arrives as argv (not baked
 * in), so ONE build serves every payload.
 */
export function dotnetDriverProgram(m: CsharpMethod): string {
  const qualClass = m.namespace ? `${m.namespace}.${m.className}` : m.className;
  const call = m.isStatic ? `${qualClass}.${m.name}(payload)` : `new ${qualClass}().${m.name}(payload)`;
  return `using System;
public static class __RaeuberDriver {
  public static void Main(string[] args) {
    var payload = args.Length > 0 ? args[0] : "";
    try {
      var r = ${call};
      Console.Write(r == null ? "" : r.ToString());
    } catch (Exception e) {
      Console.Write((e.InnerException ?? e).Message);
    }
  }
}`;
}

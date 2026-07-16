export interface CliArgs {
  dir: string;
  base: string;
  /** Restrict to explicit files instead of the git diff (mostly for tests). */
  files?: string[];
  reportFile?: string;
  prefer?: "crabbox" | "local";
  json: boolean;
}

export function parseArgs(argv: string[]): CliArgs {
  const out: Partial<CliArgs> = { base: "origin/main", json: false };
  const files: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--dir":
        out.dir = argv[++i];
        break;
      case "--base":
        out.base = argv[++i];
        break;
      case "--file":
        files.push(argv[++i]);
        break;
      case "--report-file":
        out.reportFile = argv[++i];
        break;
      case "--prefer":
        out.prefer = argv[++i] === "crabbox" ? "crabbox" : "local";
        break;
      case "--json":
        out.json = true;
        break;
      default:
        throw new Error(`raeuberkrebs: unknown argument ${a}`);
    }
  }
  if (!out.dir) throw new Error("raeuberkrebs: --dir <repo> is required");
  if (files.length) out.files = files;
  return out as CliArgs;
}

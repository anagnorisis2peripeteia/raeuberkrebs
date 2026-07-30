#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "./cli-args.js";
import { getChangedFilesFromGit } from "./git-changed-files.js";
import { runRedteam } from "./runner.js";
import { VERDICT_EXIT } from "./types.js";

function main(): number {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    console.error(
      "usage: raeuberkrebs --dir <repo> [--base <ref>] [--file <path>]... [--report-file <path>] [--prefer crabbox|local] [--json]",
    );
    return 2;
  }

  const dir = resolve(args.dir);

  let changed: string[];
  try {
    changed = args.files ?? getChangedFilesFromGit(dir, args.base);
  } catch (e) {
    // A bad --base ref, a missing merge-base, or a non-git dir must fail closed with a clear message,
    // not an uncaught stack trace (#70).
    console.error(
      `[raeuberkrebs] could not determine changed files (bad --base ref / no merge-base / not a git repo?): ` +
        `${e instanceof Error ? e.message : String(e)}`,
    );
    return 1;
  }

  const result = runRedteam(dir, changed, { sandbox: { prefer: args.prefer } });

  if (args.reportFile) {
    try {
      writeFileSync(args.reportFile, JSON.stringify(result, null, 2));
      console.error(`[raeuberkrebs] report written to ${args.reportFile}`);
    } catch (e) {
      // A failed report write must not discard an otherwise-valid verdict.
      console.error(
        `[raeuberkrebs] could not write report to ${args.reportFile}: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
  if (args.json) {
    process.stdout.write(JSON.stringify(result) + "\n");
  }

  console.error(
    `[raeuberkrebs] verdict=${result.verdict} exploits=${result.exploits.length} ` +
      `lanes=${result.lanes.map((l) => `${l.attackClass}${l.live ? "" : "(dead)"}`).join(",") || "none"} ` +
      `sandbox=${result.sandbox} elapsed=${result.elapsedMs}ms`,
  );
  for (const e of result.exploits) {
    console.error(`  [VULN] ${e.attackClass} ${e.file}:${e.line} via ${e.sink} — payload ${JSON.stringify(e.payload)}`);
  }
  if (result.error) console.error(`[raeuberkrebs] ${result.error}`);

  return VERDICT_EXIT[result.verdict];
}

process.exit(main());

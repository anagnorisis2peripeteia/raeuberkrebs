import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

function git(dir: string, args: string[]): string {
  return execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", timeout: 30_000 });
}

function lines(out: string): string[] {
  return out
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

/**
 * Derive the changed-file set for a locally staged PR: everything the branch changed since its
 * merge-base with `base`, plus staged/unstaged edits and untracked files — i.e. what a local
 * review sees before anything is pushed. Deleted files are excluded (there is nothing to attack).
 */
export function getChangedFilesFromGit(dir: string, base: string): string[] {
  const fromBranch = lines(git(dir, ["diff", "--name-only", `${base}...HEAD`]));
  const fromWorkingTree = lines(git(dir, ["diff", "--name-only", "HEAD"]));
  const untracked = lines(git(dir, ["ls-files", "--others", "--exclude-standard"]));

  const all = new Set([...fromBranch, ...fromWorkingTree, ...untracked]);
  const files = [...all].filter((file) => existsSync(join(dir, file))).sort();
  console.error(`[raeuberkrebs] changed files vs ${base}: ${files.length} total`);
  return files;
}

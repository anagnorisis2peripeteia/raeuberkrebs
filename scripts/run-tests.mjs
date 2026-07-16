#!/usr/bin/env node
// Build first (tests import from dist/), then run the node:test suite.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const win = process.platform === "win32";

const build = spawnSync("npx", ["tsc"], { cwd: ROOT, stdio: "inherit", shell: win });
if (build.status !== 0) process.exit(build.status ?? 1);

const test = spawnSync(process.execPath, ["--test", "test/*.test.mjs"], { cwd: ROOT, stdio: "inherit", shell: win });
process.exit(test.status ?? 1);

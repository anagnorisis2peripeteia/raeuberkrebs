import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// Name/identifier-field path traversal (issue #102, CWE-22). The path-traversal lane targets joins
// where an untrusted PATH component flows to a sink. It misses a common variant: a field the developer
// treats as an opaque NAME / identifier (a backup id, a package name, a manifest's `wasm_path`, an
// attachment filename) that is joined to a base directory WITHOUT a single-component check — because it
// "isn't a path", it is never validated, yet `join()` still honours `..` and (for an absolute value)
// discards the base entirely. `name = "../../x"` escapes; `name = "/abs/x"` replaces the base.
//
// The lead: a filesystem join whose component is a BARE name-field identifier (no basename / single-
// component transform on that line). A basename/secure-component wrapper, a split-and-take-last, or a
// string-literal component does NOT match — those are the documented no-fire (validated to one token).
const NAME = String.raw`\w*(?:_name|_id|_path|filename|wasm_?path|backup_?name|dest|attachment|pkg_?name|package_?name|artifact)\w*`;
const SINK_RE = new RegExp(
  String.raw`(?:\bos\.path\.join|\bposixpath\.join|\bpath\.join|\bfilepath\.Join)\s*\([^()]*?,\s*(${NAME})\s*\)` +
    String.raw`|\.join\s*\(\s*(${NAME})\s*\)` +
    String.raw`|\bPath::new\s*\([^()]*\)\.join\s*\(\s*(${NAME})\s*\)`,
  "i",
);

/**
 * Static name/identifier-field traversal lane (CWE-22). Fires a lead when a base directory is joined
 * with a bare name-field identifier (`base.join(backup_name)`, `os.path.join(root, wasm_path)`) that
 * has not passed a single-component guard — a "name" that is actually attacker-controllable path text.
 * Reuses the `path-traversal` class. `staticOnly`; leads feed the sweep (a driven variant belongs to
 * the executable path-traversal lanes).
 */
export class NameFieldTraversalAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "name-field-traversal");

  handles(file: string): boolean {
    return /\.(?:ts|mts|cts|mjs|js|cjs|py|go|rs)$/.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(SINK_RE);
      if (!m) continue;
      const field = m.slice(1).find(Boolean);
      leads.push({ line: i + 1, sink: `name-field-join:${field}` });
    }
    return leads;
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return []; // static-only: leads feed the sweep; proof is a per-lead targeted test.
  }
}

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead } from "./attacker.js";

const HERE = dirname(fileURLToPath(import.meta.url));

// eval-of-parsed-AST-source (issue #107, CWE-95). The unsafe-exec lane keys on an eval/new Function/
// vm.runIn* argument that is variable-shaped. This lane models the highest-signal real-world variant:
// an extractor that PARSES untrusted input into an AST and then `eval`s the RAW SOURCE TEXT of a node —
// the "safe-looking extractor that re-evals parsed source" shape. Cross-language (Ruby / JS / Python).
// The fix these findings all take is identical and worth encoding as the negative: extract the value
// STATICALLY (a string-literal node -> its unescaped value; anything dynamic -> nil), never eval.
//
// A dynamic-exec sink whose argument derives from a parsed node's source text:
//  - Ruby:  eval(node.slice), eval(node.loc.expression.source)
//  - JS/TS: eval(node.raw), eval(generate(node)), eval(sourceCode.getText(node))
//  - Python: eval(ast.get_source_segment(src, node)), eval(astor.to_source(node)), exec(<node source>)
const EVAL_RE =
  /\b(?:eval|exec|instance_eval|class_eval|module_eval)\s*\(|\bbinding\.eval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w*\s*\(/;
// Accessors that yield a parsed node's SOURCE TEXT (not a fixed literal). Specific enough that Array
// `.slice(0, n)` and other generic calls do not trip it: bare `.slice`/`.raw`/`.source` must sit on a
// `node`-shaped receiver; the parser-specific accessors (getText, get_source_segment, to_source,
// loc.expression.source) are unambiguous.
const NODE_SRC_RE =
  /\.loc\.expression\.source\b|\.expression\.source\b|\bsourceCode\.getText\s*\(|\.getText\s*\(\s*\w|\bget_source_segment\s*\(|\bastor\.to_source\s*\(|\.to_source\s*\(|\bgenerate\s*\(\s*\w|\bnode\w*\.(?:slice|raw|source)\b|\b\w*node\.(?:slice|raw|source)\b/i;
// A file that PARSES untrusted input — a booster that raises the eval-of-parsed-source lead to "high".
const PARSER_RE = /\b(?:ast\.parse|Prism\.parse|parser\.parse|acorn\.parse|espree\.parse|@babel|babel\.parse|\.parse_file|Ripper\.)\b/;

/**
 * Static eval-of-parsed-AST-source lane (CWE-95), extending the unsafe-exec class. Fires a lead when a
 * dynamic-exec sink's argument on the same line derives from a parsed node's source text
 * (`eval(node.slice)`, `eval(sourceCode.getText(node))`, `eval(ast.get_source_segment(...))`) — the
 * "safe extractor that re-evals parsed source" footgun. `staticOnly`; leads feed the sweep. `priority`
 * is `high` when the file also parses untrusted input (the eval arg is provably parsed text).
 */
export class EvalParsedAstAttacker implements Attacker {
  readonly attackClass = "unsafe-exec" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = resolve(HERE, "..", "..", "fixtures", "eval-parsed-ast");

  handles(file: string): boolean {
    return /\.(?:ts|mts|cts|mjs|js|cjs|py|rb)$/.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    const parses = PARSER_RE.test(source);
    const leads: StaticLead[] = [];
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!EVAL_RE.test(line) || !NODE_SRC_RE.test(line)) continue;
      // A fixed string literal argument is the negative — skip a plain `eval("...")` / `eval('...')`
      // where the whole argument is quoted (the node-source accessor requirement already excludes most).
      leads.push({ line: i + 1, sink: "eval-of-parsed-source", priority: parses ? "high" : undefined });
    }
    return leads;
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return []; // static-only: leads feed the sweep; proof is a per-lead targeted test.
  }
}

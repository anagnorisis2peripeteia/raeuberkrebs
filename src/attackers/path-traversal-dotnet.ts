import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, scanSinkLeads } from "./attacker.js";
import { DOTNET_SOURCE_RE } from "./dotnet.js";
import { UNTRUSTED_INPUT } from "./dotnet-more-lanes.js";

// Path-traversal sink in C#: a filesystem read/write/delete that takes a path — File.*, new
// FileStream. Only a LEAD; the sweep's guard-gap signal is the sharpener (a file op in a file that
// doesn't reference the project's path-containment guard, e.g. IsPathWithinRoot / ResolveLinkTarget).
const SINK_RE =
  /\bFile\.(?:ReadAll(?:Bytes|Text|Lines)|WriteAll(?:Bytes|Text|Lines)|AppendAll(?:Text|Lines)|Open(?:Read|Write|Text)?|Delete|Copy|Move|Create(?:Text)?)\s*\(|\bnew\s+FileStream\s*\(/;

/**
 * Static C# path-traversal lane. Contributes `staticLeads` to the free sweep; its value is the
 * guard-gap signal (a file sink whose file doesn't reference the project's containment guard).
 * `staticOnly` — proof is a per-lead targeted test, not an execute-driver.
 */
export class PathTraversalDotnetAttacker implements Attacker {
  readonly attackClass = "path-traversal" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = "";

  handles(file: string): boolean {
    return DOTNET_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    // Precision: only a file op in a file that surfaces gateway/remote input is attacker-reachable;
    // the SetupEngine writing its own config is not. Drops the internal-path noise.
    if (!UNTRUSTED_INPUT.test(source)) return [];
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return [];
  }
}

import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, scanSinkLeads } from "./attacker.js";
import { DOTNET_SOURCE_RE } from "./dotnet.js";

// SSRF sink in C#: an outbound HTTP request whose target is a variable (not a fixed literal URL) —
// HttpClient.*Async, WebRequest.Create, a new HttpRequestMessage. Only a LEAD; the sweep's guard-gap
// signal is the sharpener (a request sink in a file that does not reference the project's SSRF guard).
const SINK_RE =
  /\b(?:HttpClient|_http\w*|httpClient|_client|client)\s*\.\s*(?:GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|PostAsync|PutAsync|PatchAsync|DeleteAsync|SendAsync)\s*\(|\bWebRequest\.Create\s*\(|\bnew\s+HttpRequestMessage\s*\(/;

/**
 * Static C# SSRF lane. Contributes `staticLeads` to the free sweep; its value is the guard-gap
 * signal (an outbound-request sink whose file doesn't reference the project's SSRF guard — the shape
 * of the canvas.present SSRF). Marked `staticOnly` so the execute-gate skips it: driving a compiled
 * .NET request entrypoint per sink does not scale on project-dependent C#, so proof is per-lead.
 */
export class SsrfDotnetAttacker implements Attacker {
  readonly attackClass = "ssrf" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = "";

  handles(file: string): boolean {
    return DOTNET_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return []; // static-only: leads feed the sweep; proof is a per-lead targeted test.
  }
}

import type { Exploit } from "../types.js";
import type { Sandbox } from "../sandbox.js";
import { type Attacker, type StaticLead, scanSinkLeads } from "./attacker.js";
import { DOTNET_SOURCE_RE } from "./dotnet.js";
import { DOTNET_STATIC_CANARY_FIXTURE_DIR } from "./dotnet-more-lanes.js";

// Unsafe-deserialization sink in C#: a deserializer that can instantiate arbitrary types from
// attacker bytes — the classic .NET gadget surface. BinaryFormatter / LosFormatter / SoapFormatter /
// NetDataContractSerializer / ObjectStateFormatter / JavaScriptSerializer, Json.NET with
// TypeNameHandling, and XmlDocument.LoadXml (XXE). Presence is the risk; there is no common
// "sanitizer" signal, so these surface as density leads (not guard-gaps).
const SINK_RE =
  /\bBinaryFormatter\b|\bLosFormatter\b|\bSoapFormatter\b|\bNetDataContractSerializer\b|\bObjectStateFormatter\b|\bJavaScriptSerializer\b|\bTypeNameHandling\b|\bfastJSON\b|\.LoadXml\s*\(/;

/**
 * Static C# unsafe-deserialization lane. Contributes `staticLeads` to the free sweep. `staticOnly` —
 * proof (a gadget/PoC) is per-lead, not an execute-driver.
 */
export class UnsafeDeserializationDotnetAttacker implements Attacker {
  readonly attackClass = "unsafe-deserialization" as const;
  readonly staticOnly = true;
  readonly canaryFixtureDir = DOTNET_STATIC_CANARY_FIXTURE_DIR;

  handles(file: string): boolean {
    return DOTNET_SOURCE_RE.test(file);
  }

  staticLeads(source: string): StaticLead[] {
    return scanSinkLeads(source, SINK_RE);
  }

  hunt(_targetDir: string, _files: string[], _sandbox: Sandbox): Exploit[] {
    return [];
  }
}

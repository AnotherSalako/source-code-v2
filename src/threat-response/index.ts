import { env } from "../config/env";
import { ThreatResponseProvider } from "./provider";
import { NoopThreatResponseProvider } from "./noop";
import { CrowdStrikeThreatResponseProvider } from "./providers/crowdstrike";

// Single shared instance, selected by THREAT_RESPONSE_PROVIDER — the only
// place in the app that constructs one. Mirrors src/crypto/index.ts's
// buildKmsProvider() pattern.
function buildThreatResponseProvider(): ThreatResponseProvider {
  if (env.threatResponseProvider === "crowdstrike") {
    return new CrowdStrikeThreatResponseProvider(env.crowdStrikeClientId!, env.crowdStrikeClientSecret!, env.crowdStrikeBaseUrl);
  }
  return new NoopThreatResponseProvider();
}

export const threatResponse: ThreatResponseProvider = buildThreatResponseProvider();
export * from "./provider";

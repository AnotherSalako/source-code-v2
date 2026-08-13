import { ContainmentResult, ThreatResponseProvider } from "./provider";

/**
 * Default provider — takes no action and says so plainly, rather than
 * pretending to succeed. This is what's active until THREAT_RESPONSE_PROVIDER
 * is set to a real one with real credentials.
 */
export class NoopThreatResponseProvider implements ThreatResponseProvider {
  async containHost(hostIdentifier: string): Promise<ContainmentResult> {
    return {
      success: false,
      message:
        `No active-response provider is configured — nothing was done to "${hostIdentifier}". ` +
        `Set THREAT_RESPONSE_PROVIDER=crowdstrike (and its credentials) to enable real host containment.`,
    };
  }
}

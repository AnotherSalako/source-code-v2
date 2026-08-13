export interface ContainmentResult {
  success: boolean;
  message: string;
}

/**
 * Swappable active-response boundary, same pattern as KmsProvider
 * (src/crypto/kms.ts). Deliberately narrow: one action — network
 * containment of a host — because that's the one EDR primitive that's both
 * (a) widely supported via API and (b) reversible if it fires on a false
 * positive ("lift containment" undoes it). This app never deletes files,
 * kills processes, or blocks traffic directly; it asks a system that
 * already has scoped, consented authority over the target to do that.
 *
 * Always invoked by a human clicking a button (POST
 * .../findings/:id/response-actions/contain), never automatically — see
 * src/modules/findings/findings.routes.ts.
 */
export interface ThreatResponseProvider {
  containHost(hostIdentifier: string): Promise<ContainmentResult>;
}

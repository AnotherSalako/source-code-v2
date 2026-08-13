import { ESignatureProvider, SendForSignatureParams, SendResult, StatusResult } from "./provider";

/**
 * Default provider — the routes that use ESignatureProvider check for this
 * and respond with a clear "not configured, use manual authorization
 * instead" rather than pretending to send anything. The existing manual
 * self-attestation flow (POST /engagements/:id/authorize) keeps working
 * unchanged regardless of this — e-signature is an upgrade path, not a
 * replacement requirement.
 */
export class NoopESignatureProvider implements ESignatureProvider {
  async sendForSignature(_params: SendForSignatureParams): Promise<SendResult> {
    throw new Error("No e-signature provider configured. Set ESIGNATURE_PROVIDER=documenso, or use manual authorization instead.");
  }
  async checkStatus(_envelopeId: string): Promise<StatusResult> {
    throw new Error("No e-signature provider configured.");
  }
  async getSignedDocument(_envelopeId: string): Promise<Buffer | null> {
    return null;
  }
}

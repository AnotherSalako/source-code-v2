export interface SendForSignatureParams {
  documentBuffer: Buffer;
  documentName: string;
  signerEmail: string;
  signerName: string;
  externalId: string; // engagementId — for correlating provider-side records back to ours
}

export interface SendResult {
  envelopeId: string;
  signingUrl?: string;
}

export interface StatusResult {
  status: "SENT" | "SIGNED" | "DECLINED" | "VOIDED";
  signedAt?: Date;
}

/**
 * Swappable e-signature boundary, same pattern as KmsProvider/
 * ThreatResponseProvider. Send a document out for signature, check whether
 * it's been signed, and fetch the completed signed PDF once it has. The
 * engagement's authorizationSignedAt/authorizedBy only get set once
 * checkStatus reports SIGNED (src/modules/engagements/engagements.routes.ts)
 * — this is a *verification* mechanism replacing self-attestation, not a
 * UI nicety.
 */
export interface ESignatureProvider {
  sendForSignature(params: SendForSignatureParams): Promise<SendResult>;
  checkStatus(envelopeId: string): Promise<StatusResult>;
  /** Returns null if the provider has no completed document yet (or doesn't support fetching one). */
  getSignedDocument(envelopeId: string): Promise<Buffer | null>;
}

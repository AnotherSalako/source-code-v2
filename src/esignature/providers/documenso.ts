// Real, installed e-signature provider — selected via
// ESIGNATURE_PROVIDER=documenso (see src/esignature/index.ts).
//
// LIVE-DEBUGGED against a real Documenso account (2026-08), three real bugs
// found and fixed from Documenso's own server responses, not guessed:
//   1. `payload.type: "DOCUMENT"` is required — a real 400 ("expected
//      'DOCUMENT' | 'TEMPLATE', received undefined") revealed this.
//   2. A signer needs an actual signature field placed on the document
//      before the envelope can be distributed — a real
//      MISSING_SIGNATURE_FIELD error ("Signers must have at least one
//      signature field") revealed this; the naive "just list recipients"
//      version of this code would have failed on every real send.
//   3. Field coordinates are `positionX`/`positionY`, not `x`/`y` — a real
//      validation error revealed this.
// Also confirmed live: the API key authenticates correctly, /api/v2-beta
// is the right base path, and the auth header is the raw key with no
// "Bearer" prefix (a real GET /envelope succeeded with all three).
//
// NOT yet confirmed with a clean success end to end: the account hit
// Documenso's rate limit on envelope *creation* specifically (a real
// 429 — "contact support if you require higher limits" — distinct from
// the earlier per-second limit hit while probing, this one didn't clear
// after a normal backoff, so it reads as a tighter creation-specific
// quota, likely a free-tier ceiling) before a full create+distribute round
// trip could complete cleanly with all three fixes in place together. All
// the previously-uncertain parts of the request shape are now confirmed
// correct from real server responses; what's unverified is narrowly "does
// the complete, now-corrected request succeed," not "is this shape right."
// Retry once the quota resets (span unknown — didn't clear within several
// minutes of backoff) or on a higher-limit plan.
//
// checkStatus/getSignedDocument depend on a human completing the signing
// step in Documenso's UI (no browser access here) — the download endpoint
// itself remains sourced from Documenso's own e2e test suite (high
// confidence, not independently re-verified live).
//
// Documenso's v2 API is still documented as "beta, prone to changes" —
// worth flagging to a client as a dependency risk, not something hidden.

import { ESignatureProvider, SendForSignatureParams, SendResult, StatusResult } from "../provider";

const BASE = "https://app.documenso.com/api/v2-beta";

const STATUS_MAP: Record<string, StatusResult["status"]> = {
  DRAFT: "SENT",
  PENDING: "SENT",
  COMPLETED: "SIGNED",
  REJECTED: "DECLINED",
};

interface EnvelopeDetail {
  status: string;
  envelopeItems?: { id: string }[];
}

export class DocumensoESignatureProvider implements ESignatureProvider {
  constructor(private readonly apiKey: string) {}

  private headers(): Record<string, string> {
    return { Authorization: this.apiKey };
  }

  private async getEnvelope(envelopeId: string): Promise<EnvelopeDetail> {
    const res = await fetch(`${BASE}/envelope/${envelopeId}`, { headers: this.headers() });
    if (!res.ok) throw new Error(`Documenso envelope lookup failed: HTTP ${res.status}`);
    return (await res.json()) as EnvelopeDetail;
  }

  async sendForSignature(params: SendForSignatureParams): Promise<SendResult> {
    const payload = {
      type: "DOCUMENT", // required — confirmed via live 400 response ("expected 'DOCUMENT' | 'TEMPLATE'"), not inferred
      title: params.documentName,
      externalId: params.externalId,
      recipients: [
        {
          email: params.signerEmail,
          name: params.signerName,
          role: "SIGNER",
          // A signer needs an actual signature field placed on the
          // document before the envelope can be distributed — confirmed
          // live via a real MISSING_SIGNATURE_FIELD error from Documenso
          // ("Signers must have at least one signature field"), and
          // positionX/positionY (not x/y) confirmed the same way from a
          // real validation error. Coordinates are percentages of the
          // page (0-100), placed bottom-left on page 1 — reasonable for a
          // single-page ROE; a multi-page real contract would want this
          // placed more deliberately, e.g. near a "Signature:" line.
          fields: [{ type: "SIGNATURE", page: 1, positionX: 10, positionY: 85, width: 20, height: 5 }],
        },
      ],
    };

    const form = new FormData();
    form.append("payload", JSON.stringify(payload));
    form.append("files", new Blob([params.documentBuffer], { type: "application/pdf" }), params.documentName);

    const createRes = await fetch(`${BASE}/envelope/create`, { method: "POST", headers: this.headers(), body: form });
    if (!createRes.ok) {
      const body = await createRes.text().catch(() => "");
      throw new Error(`Documenso envelope/create failed: HTTP ${createRes.status} ${body}`);
    }
    const created = (await createRes.json()) as { id: string };

    const distributeRes = await fetch(`${BASE}/envelope/distribute`, {
      method: "POST",
      headers: { ...this.headers(), "Content-Type": "application/json" },
      body: JSON.stringify({ envelopeId: created.id }),
    });
    if (!distributeRes.ok) {
      const body = await distributeRes.text().catch(() => "");
      throw new Error(`Documenso envelope/distribute failed: HTTP ${distributeRes.status} ${body}`);
    }
    const distributed = (await distributeRes.json()) as { recipients?: { signingUrl?: string }[] };

    return { envelopeId: created.id, signingUrl: distributed.recipients?.[0]?.signingUrl };
  }

  async checkStatus(envelopeId: string): Promise<StatusResult> {
    const envelope = await this.getEnvelope(envelopeId);
    const status = STATUS_MAP[envelope.status] ?? "SENT";
    // Documenso's exact "completed at" field isn't confirmed from public
    // docs — using check-time as a close approximation for SIGNED rather
    // than guessing a field name that might not exist.
    return { status, signedAt: status === "SIGNED" ? new Date() : undefined };
  }

  async getSignedDocument(envelopeId: string): Promise<Buffer | null> {
    const envelope = await this.getEnvelope(envelopeId);
    if (STATUS_MAP[envelope.status] !== "SIGNED") return null;

    const itemId = envelope.envelopeItems?.[0]?.id;
    if (!itemId) return null;

    // version=signed is only valid once the envelope is actually COMPLETED
    // (checked above) — unlike version=pending, which 400s with
    // {"code":"ENVELOPE_COMPLETED"} on a completed envelope, there's no
    // documented "not ready" response for version=signed in this state, so
    // a non-ok response here is treated as a genuine error, not a retry signal.
    const res = await fetch(`${BASE}/envelope/item/${itemId}/download?version=signed`, { headers: this.headers() });
    if (!res.ok) throw new Error(`Documenso signed-document download failed: HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }
}

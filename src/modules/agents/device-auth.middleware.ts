import { NextFunction, Request, Response } from "express";
import crypto from "crypto";
import { prisma } from "../../db/prisma";
import { verifyDeviceSignature } from "./ca";

// How far a request's timestamp may drift from server time before it's
// rejected — bounds both clock skew tolerance and the outer edge of the
// replay window (a captured, previously-valid signed request stops working
// after this long even if nothing else about the design changed).
const REQUEST_SIGNATURE_WINDOW_MS = 5 * 60 * 1000;

function bodySha256Base64(req: Request): string {
  // express.json() has already parsed req.body by the time this runs
  // (app.ts mounts it before any router) — re-serialize deterministically
  // the same way the agent does before signing: compact JSON, or an empty
  // string for a body-less request (GET, DELETE-without-body).
  const raw = req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : "";
  return crypto.createHash("sha256").update(raw, "utf8").digest("base64");
}

/**
 * Authenticates a request as coming from a specific, still-active Device —
 * the agent equivalent of requireAuth, but there's no session and no user:
 * identity is proven by a fresh Ed25519 signature over this exact request,
 * checked against the public key recorded at enrollment (see ca.ts). No
 * re-verification of the CA-issued credential happens here — once a Device
 * row exists, that row is the source of truth, and revocation is checked
 * on every single call by requiring status === "ACTIVE", not by anything
 * cert-expiry-shaped.
 */
export async function requireDeviceAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const deviceId = req.header("x-jupiter-device-id");
  const timestampHeader = req.header("x-jupiter-timestamp");
  const signature = req.header("x-jupiter-signature");

  if (!deviceId || !timestampHeader || !signature) {
    res.status(401).json({ error: "Missing device authentication headers" });
    return;
  }

  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() - timestamp * 1000) > REQUEST_SIGNATURE_WINDOW_MS) {
    // Same message whether the timestamp is malformed or just stale — no
    // reason to help an attacker distinguish "clock skew" from "replay".
    res.status(401).json({ error: "Request timestamp missing, malformed, or outside the allowed window" });
    return;
  }

  const device = await prisma.device.findUnique({ where: { id: deviceId } });
  if (!device || device.status !== "ACTIVE") {
    res.status(401).json({ error: "Unknown or revoked device" });
    return;
  }

  const signedPayload = `${req.method}.${req.originalUrl}.${timestamp}.${bodySha256Base64(req)}`;
  if (!verifyDeviceSignature(device.publicKeyBase64, Buffer.from(signedPayload, "utf8"), signature)) {
    res.status(401).json({ error: "Invalid request signature" });
    return;
  }

  req.device = { id: device.id, clientId: device.clientId };
  next();
}

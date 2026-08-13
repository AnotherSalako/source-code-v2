import crypto from "crypto";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";

// Endpoint-agent enrollment (see prisma/schema.prisma "Endpoint agent
// enrollment" section for the full design rationale). No X.509/TLS anywhere
// here — nothing in this system does certificate-chain validation, so a
// real certificate would just be attack surface with no corresponding
// check. Ed25519 throughout instead, keyed by raw 32-byte public keys /
// 64-byte signatures (base64 on the wire) rather than DER/PEM — simpler to
// reason about, and matches exactly what the Rust agent's ed25519-dalek
// produces natively.
//
// This app's CA private key gets the exact same custody treatment every
// other key in this app gets (src/crypto/envelope.ts): wrapped by the
// system KMS, decrypted fresh from the DB on every use rather than cached
// in memory — deliberately not optimized, since signing an enrollment
// credential is rare (once per device, not a request-path hot path) and
// "never held longer than the operation needs it" matters more here than
// saving one KMS round trip.

const CA_ROW_ID = "default";

function jwkPublicKey(rawBase64: string): crypto.KeyObject {
  const raw = Buffer.from(rawBase64, "base64");
  return crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
}

function jwkPrivateKey(seedBase64: string, publicRawBase64: string): crypto.KeyObject {
  const seed = Buffer.from(seedBase64, "base64");
  const pub = Buffer.from(publicRawBase64, "base64");
  return crypto.createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", x: pub.toString("base64url"), d: seed.toString("base64url") },
    format: "jwk",
  });
}

/** Creates the app's one CA keypair on first use; loads it on every call after. */
async function loadOrCreateCaRow() {
  const existing = await prisma.agentCaKey.findUnique({ where: { id: CA_ROW_ID } });
  if (existing) return existing;

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubJwk = publicKey.export({ format: "jwk" }) as { x: string };
  const privJwk = privateKey.export({ format: "jwk" }) as { d: string };
  const publicKeyBase64 = Buffer.from(pubJwk.x, "base64url").toString("base64");
  const seedBase64 = Buffer.from(privJwk.d, "base64url").toString("base64");

  // A second concurrent cold start could race this create — the unique id
  // ("default") makes that a P2002 conflict, not two live CA keys; fall
  // back to reading whichever row won.
  try {
    return await prisma.agentCaKey.create({
      data: {
        id: CA_ROW_ID,
        publicKeyBase64,
        privateSeedEnc: (await encryptField(kms, seedBase64, "agentCa:privateSeed")) as any,
      },
    });
  } catch {
    return await prisma.agentCaKey.findUniqueOrThrow({ where: { id: CA_ROW_ID } });
  }
}

export async function caPublicKeyBase64(): Promise<string> {
  const row = await loadOrCreateCaRow();
  return row.publicKeyBase64;
}

/** The exact, position-fixed string a credential's signature covers — no JSON-canonicalization ambiguity. */
export function credentialPayload(deviceId: string, clientId: string, devicePublicKeyBase64: string, issuedAtUnixSeconds: number): string {
  return `${deviceId}.${clientId}.${devicePublicKeyBase64}.${issuedAtUnixSeconds}`;
}

/** Signs a new device's enrollment credential. Recorded for audit/display — day-to-day requests are verified against the device's own stored key, not by re-checking this. */
export async function signCredential(
  deviceId: string,
  clientId: string,
  devicePublicKeyBase64: string,
  issuedAtUnixSeconds: number
): Promise<string> {
  const row = await loadOrCreateCaRow();
  const seedBase64 = await decryptField(kms, row.privateSeedEnc as any, "agentCa:privateSeed");
  const privateKey = jwkPrivateKey(seedBase64, row.publicKeyBase64);
  const payload = Buffer.from(credentialPayload(deviceId, clientId, devicePublicKeyBase64, issuedAtUnixSeconds), "utf8");
  return crypto.sign(null, payload, privateKey).toString("base64");
}

/** Verifies a signature made by a DEVICE's own key — the actual per-request auth check (src/modules/agents/device-auth.middleware.ts), not CA-related, but the same Ed25519 primitive lives here alongside it. */
export function verifyDeviceSignature(devicePublicKeyBase64: string, data: Buffer, signatureBase64: string): boolean {
  try {
    const pub = jwkPublicKey(devicePublicKeyBase64);
    return crypto.verify(null, data, pub, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

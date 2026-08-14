import { Router } from "express";
import { z } from "zod";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { encryptField } from "../../crypto/envelope";
import { verifyKmsCredential } from "../../crypto/kms-verify";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";
import { sideEffectLimiter } from "../../middleware/rate-limit";
import { writeAuditLog } from "../audit/audit.service";

export const byokRouter = Router();

// Real BYOK, not a second name for the existing per-tenant-key feature —
// this reaches a key in the client's *own* AWS account, via their own
// credentials, not a key inside this app's own configured KMS account.
// See src/crypto/tenant.ts's tenantKms() for the priority order this
// slots into, and schema.prisma's ClientKmsCredential comment for why the
// credential itself is always encrypted under the system key, never a
// tenant key.

const credentialSchema = z.object({
  keyId: z.string().trim().min(1).max(500),
  region: z.string().trim().min(1).max(50),
  accessKeyId: z.string().trim().min(1).max(200),
  secretAccessKey: z.string().trim().min(1).max(200),
});

byokRouter.put("/clients/:id/kms-credential", requireAuth, requireRole("SECURITY_ADMIN"), sideEffectLimiter, async (req, res) => {
  const parsed = credentialSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const client = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!client) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const check = await verifyKmsCredential(parsed.data);
  if (!check.valid) {
    res.status(400).json({ error: `This credential can't GenerateDataKey/Decrypt against that key: ${check.error}` });
    return;
  }

  // System key, not tenantKms(client.id) — see this file's top comment.
  await prisma.clientKmsCredential.upsert({
    where: { clientId: client.id },
    create: {
      clientId: client.id,
      keyId: parsed.data.keyId,
      region: parsed.data.region,
      accessKeyIdEnc: (await encryptField(kms, parsed.data.accessKeyId, `clientKmsCredential:accessKeyId`)) as any,
      secretAccessKeyEnc: (await encryptField(kms, parsed.data.secretAccessKey, `clientKmsCredential:secretAccessKey`)) as any,
      createdBy: req.user!.id,
    },
    update: {
      keyId: parsed.data.keyId,
      region: parsed.data.region,
      accessKeyIdEnc: (await encryptField(kms, parsed.data.accessKeyId, `clientKmsCredential:accessKeyId`)) as any,
      secretAccessKeyEnc: (await encryptField(kms, parsed.data.secretAccessKey, `clientKmsCredential:secretAccessKey`)) as any,
    },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "UPDATE",
    resourceType: "client.kmsCredential",
    resourceId: client.id,
    result: "SUCCESS",
  });

  res.json({ configured: true, region: parsed.data.region, keyId: parsed.data.keyId });
});

// Status only, same write-only discipline as CSPM's cloud-credentials and
// an enrollment token — the secret is never returned once stored.
byokRouter.get("/clients/:id/kms-credential", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const credential = await prisma.clientKmsCredential.findUnique({ where: { clientId: req.params.id } });
  if (!credential) {
    res.json({ configured: false });
    return;
  }
  res.json({ configured: true, keyId: credential.keyId, region: credential.region });
});

byokRouter.delete("/clients/:id/kms-credential", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const credential = await prisma.clientKmsCredential.findUnique({ where: { clientId: req.params.id } });
  if (!credential) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  await prisma.clientKmsCredential.delete({ where: { clientId: req.params.id } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DELETE",
    resourceType: "client.kmsCredential",
    resourceId: req.params.id,
    result: "SUCCESS",
  });

  // Deliberately does NOT touch already-encrypted data: exactly like
  // reassigning Client.kmsKeyId, EncryptedField.kmsKeyId travels with each
  // record, so removing this credential only affects *new* encryptions
  // (which fall back to the next tier in tenantKms()'s priority order) —
  // existing ciphertext wrapped under the client's own key becomes
  // undecryptable from this app's side, which is the correct, honest
  // consequence of BYOK: this app never had independent custody of that
  // key to begin with.
  res.json({ deleted: true });
});

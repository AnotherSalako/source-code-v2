import { Router } from "express";
import { z } from "zod";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";
import { sideEffectLimiter } from "../../middleware/rate-limit";
import { writeAuditLog } from "../audit/audit.service";
import { runCspmScan, verifyCredentials } from "./cspm-scanner";

export const cspmRouter = Router();

// Same "no assertOwnOrg needed" precedent as PATCH /clients/:id/kms-key —
// gated entirely by requireRole("SECURITY_ADMIN"), which is already
// org-exempt trusted staff, not a client-facing role. A client's own users
// never see or manage these credentials at all.

const credentialsSchema = z.object({
  accessKeyId: z.string().trim().min(1).max(200),
  secretAccessKey: z.string().trim().min(1).max(200),
  region: z.string().trim().min(1).max(50),
});

// One real read-only AWS call (verifyCredentials, cspm-scanner.ts) before
// anything is ever written — storing a credential that doesn't actually
// authenticate would just be an encrypted string nobody could use, and the
// only way to know it authenticates is to actually ask AWS, not assume the
// shape of an access key ID is proof of anything.
cspmRouter.put("/clients/:id/cloud-credentials", requireAuth, requireRole("SECURITY_ADMIN"), sideEffectLimiter, async (req, res) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const client = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!client) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const check = await verifyCredentials(parsed.data);
  if (!check.valid) {
    res.status(400).json({ error: `These credentials don't authenticate against AWS: ${check.error}` });
    return;
  }

  const scopedKms = await tenantKms(client.id);
  await prisma.cloudCredential.upsert({
    where: { clientId: client.id },
    create: {
      clientId: client.id,
      accessKeyIdEnc: (await encryptField(scopedKms, parsed.data.accessKeyId, `cloudCredential:accessKeyId`)) as any,
      secretAccessKeyEnc: (await encryptField(scopedKms, parsed.data.secretAccessKey, `cloudCredential:secretAccessKey`)) as any,
      region: parsed.data.region,
      createdBy: req.user!.id,
    },
    update: {
      accessKeyIdEnc: (await encryptField(scopedKms, parsed.data.accessKeyId, `cloudCredential:accessKeyId`)) as any,
      secretAccessKeyEnc: (await encryptField(scopedKms, parsed.data.secretAccessKey, `cloudCredential:secretAccessKey`)) as any,
      region: parsed.data.region,
    },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "UPDATE",
    resourceType: "client.cloudCredential",
    resourceId: client.id,
    result: "SUCCESS",
  });

  res.json({ configured: true, region: parsed.data.region });
});

// Status only — the secret itself is never returned once stored, same
// write-only discipline as an enrollment token. "Is something configured"
// is the only question this answers.
cspmRouter.get("/clients/:id/cloud-credentials", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const credential = await prisma.cloudCredential.findUnique({ where: { clientId: req.params.id } });
  if (!credential) {
    res.json({ configured: false });
    return;
  }
  res.json({ configured: true, provider: credential.provider, region: credential.region, lastScannedAt: credential.lastScannedAt });
});

cspmRouter.delete("/clients/:id/cloud-credentials", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const credential = await prisma.cloudCredential.findUnique({ where: { clientId: req.params.id } });
  if (!credential) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  await prisma.cloudCredential.delete({ where: { clientId: req.params.id } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DELETE",
    resourceType: "client.cloudCredential",
    resourceId: req.params.id,
    result: "SUCCESS",
  });

  res.json({ deleted: true });
});

// Computed on demand, like /findings/clusters and /attack-paths — nothing
// here is persisted as a Finding automatically. A CspmIssue doesn't fit
// Finding's shape any more than a WatchAlert does (no Test, no pentest
// severity/CVSS workflow) — a human reviewing these decides what, if
// anything, becomes a tracked Finding.
cspmRouter.post("/clients/:id/cspm-scan", requireAuth, requireRole("SECURITY_ADMIN"), sideEffectLimiter, async (req, res) => {
  const credential = await prisma.cloudCredential.findUnique({ where: { clientId: req.params.id } });
  if (!credential) {
    res.status(400).json({ error: "No cloud credentials configured for this client yet — PUT /clients/:id/cloud-credentials first" });
    return;
  }

  const accessKeyId = await decryptField(kms, credential.accessKeyIdEnc as any, `cloudCredential:accessKeyId`);
  const secretAccessKey = await decryptField(kms, credential.secretAccessKeyEnc as any, `cloudCredential:secretAccessKey`);

  const issues = await runCspmScan({ accessKeyId, secretAccessKey, region: credential.region });

  await prisma.cloudCredential.update({ where: { clientId: req.params.id }, data: { lastScannedAt: new Date() } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "client.cspmScan",
    resourceId: req.params.id,
    result: "SUCCESS",
  });

  res.json({ issues, scannedAt: new Date() });
});

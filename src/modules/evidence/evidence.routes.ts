import { createHash } from "crypto";
import { Router } from "express";
import multer from "multer";
import { z } from "zod";
import { prisma } from "../../db/prisma";
import { kms, objectStorage } from "../../crypto";
import { encryptBuffer, decryptBuffer } from "../../crypto/envelope";
import { newStorageKey } from "../../crypto/storage";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { checkEvidenceMalware } from "../../integrations/malware-check";
import { env } from "../../config/env";

export const evidenceRouter = Router({ mergeParams: true });

// In-memory upload buffer is fine at MVP scale (scan screenshots/logs, not
// multi-GB pcaps); stream-encrypt to disk instead if evidence sizes grow.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// originalFilename is user-controlled (whatever the uploader's file was
// named) and lands directly in a Content-Disposition header — strip CR/LF
// (header injection) and quotes (breaking out of the quoted filename value)
// before it's ever interpolated there.
export function sanitizeFilenameForHeader(name: string): string {
  return name.replace(/[\r\n"]/g, "");
}

evidenceRouter.post(
  "/findings/:findingId/evidence",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  upload.single("file"),
  async (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: "Missing file field" });
      return;
    }
    const { findingId } = req.params;

    // Hashed from the plaintext before encryption — the hash itself isn't
    // sensitive (can't be reversed to the file) and lets a malware check run
    // against the file's reputation without ever sending the file itself
    // anywhere.
    const sha256 = createHash("sha256").update(req.file.buffer).digest("hex");

    const encrypted = await encryptBuffer(kms, req.file.buffer, `evidence:${findingId}`);
    const storageKey = newStorageKey(`evidence/${findingId}`);
    await objectStorage.put(storageKey, encrypted.ciphertext);

    const evidence = await prisma.evidence.create({
      data: {
        findingId,
        originalFilename: req.file.originalname,
        mimeType: req.file.mimetype,
        storageKey,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        encryptedDataKey: encrypted.encryptedDataKey,
        kmsKeyId: encrypted.kmsKeyId,
        keyVersion: encrypted.keyVersion,
        sizeBytes: req.file.size,
        uploadedBy: req.user!.id,
        sha256,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "evidence",
      resourceId: evidence.id,
      result: "SUCCESS",
    });

    void checkEvidenceMalware(evidence.id, sha256); // fire-and-forget — never blocks the upload response

    res.status(201).json({ id: evidence.id, filename: evidence.originalFilename });
  }
);

// --- Presigned direct-to-storage upload ------------------------------------
// The multipart route above sends the file through this server's own request
// body — fine locally, but Vercel's serverless default (4.5MB) rejects
// anything bigger, and evidence (screen recordings, pcaps) routinely isn't.
// This two-step flow lets the browser upload ciphertext straight to object
// storage, bypassing this server for the bytes entirely:
//   1. presign  — server mints a DEK + a one-time upload URL/token
//   2. (browser encrypts client-side with WebCrypto and PUTs the ciphertext
//      directly to storage using that URL/token — never touches this server)
//   3. complete — server records the Evidence row from what the browser
//      reports, after confirming the object actually landed in storage
//
// Only available when the configured ObjectStorage provider supports it
// (Supabase does; local-disk dev storage doesn't, since there's no
// meaningful "presigned URL" for your own filesystem and no size-limit
// problem to solve there anyway) — the frontend falls back to the regular
// multipart route when this 501s.

const presignSchema = z.object({
  originalFilename: z.string().trim().min(1).max(255),
  mimeType: z.string().trim().min(1).max(255),
});

evidenceRouter.post(
  "/findings/:findingId/evidence/presign",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    if (!objectStorage.createUploadUrl) {
      res.status(501).json({
        error: "The configured storage backend doesn't support presigned uploads — use the regular upload instead.",
      });
      return;
    }
    const parsed = presignSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { findingId } = req.params;
    const finding = await prisma.finding.findUnique({
      where: { id: findingId },
      include: { test: { include: { engagement: { select: { clientId: true } } } } },
    });
    if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const storageKey = newStorageKey(`evidence/${findingId}`);
    const { url, token } = await objectStorage.createUploadUrl(storageKey);

    // Generated directly (not via encryptBuffer, which would also do the
    // encrypting) — the browser does the actual AES-256-GCM encryption
    // client-side with this DEK, using the exact same format
    // (12-byte IV, AAD = `evidence:${findingId}`) src/crypto/envelope.ts
    // uses server-side, so either path decrypts identically later.
    const { plaintextKey, encryptedDataKey, keyId, keyVersion } = await kms.generateDataKey();

    res.json({
      storageKey,
      bucket: env.supabaseStorageBucket,
      uploadUrl: url,
      uploadToken: token,
      aad: `evidence:${findingId}`,
      dek: plaintextKey.toString("base64"),
      encryptedDataKey: encryptedDataKey.toString("base64"),
      kmsKeyId: keyId,
      keyVersion,
    });
    plaintextKey.fill(0);
  }
);

const completeSchema = z.object({
  storageKey: z.string().min(1),
  iv: z.string().min(1),
  authTag: z.string().min(1),
  encryptedDataKey: z.string().min(1),
  kmsKeyId: z.string().min(1),
  keyVersion: z.number().int(),
  originalFilename: z.string().trim().min(1).max(255),
  mimeType: z.string().trim().min(1).max(255),
  sizeBytes: z.number().int().positive(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/, "must be a 64-char lowercase hex SHA-256"),
});

evidenceRouter.post(
  "/findings/:findingId/evidence/complete",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = completeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { findingId } = req.params;
    const finding = await prisma.finding.findUnique({
      where: { id: findingId },
      include: { test: { include: { engagement: { select: { clientId: true } } } } },
    });
    if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const d = parsed.data;

    if (objectStorage.exists && !(await objectStorage.exists(d.storageKey))) {
      res.status(400).json({ error: "No object found at that storage key — the upload didn't actually land. Retry it." });
      return;
    }

    const evidence = await prisma.evidence.create({
      data: {
        findingId,
        originalFilename: d.originalFilename,
        mimeType: d.mimeType,
        storageKey: d.storageKey,
        iv: d.iv,
        authTag: d.authTag,
        encryptedDataKey: d.encryptedDataKey,
        kmsKeyId: d.kmsKeyId,
        keyVersion: d.keyVersion,
        sizeBytes: d.sizeBytes,
        uploadedBy: req.user!.id,
        sha256: d.sha256,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "evidence",
      resourceId: evidence.id,
      result: "SUCCESS",
    });

    void checkEvidenceMalware(evidence.id, d.sha256);

    res.status(201).json({ id: evidence.id, filename: evidence.originalFilename });
  }
);

// List is metadata-only (filename/size) — no ciphertext read, no decrypt, so
// browsing a finding's evidence list doesn't itself trigger a DOWNLOAD audit
// entry. That only happens per-file, on the actual download below.
evidenceRouter.get("/findings/:findingId/evidence", requireAuth, async (req, res) => {
  const finding = await prisma.finding.findUnique({
    where: { id: req.params.findingId },
    include: { test: { include: { engagement: { select: { clientId: true } } } } },
  });
  if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  if (req.user!.role === "EXEC_CLIENT") {
    res.json([]);
    return;
  }

  const evidence = await prisma.evidence.findMany({
    where: { findingId: req.params.findingId },
    select: {
      id: true,
      originalFilename: true,
      mimeType: true,
      sizeBytes: true,
      uploadedAt: true,
      malwareStatus: true,
      malwareDetections: true,
    },
    orderBy: { uploadedAt: "desc" },
  });

  res.json(evidence);
});

evidenceRouter.get(
  "/findings/:findingId/evidence/:evidenceId",
  requireAuth,
  async (req, res) => {
    const evidence = await prisma.evidence.findUnique({
      where: { id: req.params.evidenceId },
      include: { finding: { include: { test: { include: { engagement: { select: { clientId: true } } } } } } },
    });
    if (
      !evidence ||
      evidence.findingId !== req.params.findingId ||
      !assertOwnOrg(req, evidence.finding.test.engagement.clientId)
    ) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    // Raw exploitation evidence (screenshots, shells, logs) is for internal
    // security staff / technical client teams, not the exec business-risk view.
    if (req.user!.role === "EXEC_CLIENT") {
      await writeAuditLog(prisma, {
        userId: req.user!.id,
        action: "DOWNLOAD",
        resourceType: "evidence",
        resourceId: evidence.id,
        result: "DENIED",
      });
      res.status(403).json({ error: "Executive role cannot access raw evidence files" });
      return;
    }

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "DOWNLOAD",
      resourceType: "evidence",
      resourceId: evidence.id,
      result: "SUCCESS",
    });

    const ciphertext = await objectStorage.get(evidence.storageKey);
    const plaintext = await decryptBuffer(
      kms,
      {
        ciphertext,
        iv: evidence.iv,
        authTag: evidence.authTag,
        encryptedDataKey: evidence.encryptedDataKey,
        kmsKeyId: evidence.kmsKeyId,
      },
      `evidence:${evidence.findingId}`
    );

    res.setHeader("Content-Type", evidence.mimeType);
    res.setHeader("Content-Disposition", `attachment; filename="${sanitizeFilenameForHeader(evidence.originalFilename)}"`);
    res.send(plaintext);
  }
);

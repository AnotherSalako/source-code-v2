import { Router } from "express";
import { z } from "zod";
import multer from "multer";
import { prisma } from "../../db/prisma";
import { kms, objectStorage } from "../../crypto";
import { encryptField, decryptField, encryptBuffer, decryptBuffer, EncryptedField } from "../../crypto/envelope";
import { newStorageKey } from "../../crypto/storage";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { esignature } from "../../esignature";
import { logger } from "../../config/logger";
import { sideEffectLimiter } from "../../middleware/rate-limit";

export const engagementsRouter = Router();

const uploadRoeDoc = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

const createSchema = z.object({
  clientId: z.string().uuid(),
  assumptions: z.string().max(10_000).optional(),
  exclusions: z.string().max(10_000).optional(),
});

engagementsRouter.post("/", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { clientId, assumptions, exclusions } = parsed.data;

  const engagement = await prisma.engagement.create({
    data: {
      clientId,
      assumptionsEnc: assumptions
        ? ((await encryptField(kms, assumptions, `engagement:assumptions`)) as EncryptedField as any)
        : undefined,
      exclusionsEnc: exclusions
        ? ((await encryptField(kms, exclusions, `engagement:exclusions`)) as EncryptedField as any)
        : undefined,
    },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "CREATE",
    resourceType: "engagement",
    resourceId: engagement.id,
    engagementId: engagement.id,
    result: "SUCCESS",
  });

  res.status(201).json(engagement);
});

// Admin sees every engagement (optionally filtered to one client via
// ?clientId=); client-side users only ever see their own org's engagements.
engagementsRouter.get("/", requireAuth, async (req, res) => {
  const { clientId } = req.query;
  const isAdmin = req.user!.role === "SECURITY_ADMIN";

  if (!isAdmin && typeof clientId === "string" && clientId !== req.user!.orgId) {
    res.json([]);
    return;
  }

  const engagements = await prisma.engagement.findMany({
    where: {
      clientId: isAdmin ? (typeof clientId === "string" ? clientId : undefined) : req.user!.orgId ?? "",
    },
    orderBy: { createdAt: "desc" },
    include: { client: { select: { id: true, name: true } } },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "engagement",
    resourceId: null,
    result: "SUCCESS",
  });

  res.json(engagements);
});

engagementsRouter.get("/:id", requireAuth, async (req, res) => {
  const engagement = await prisma.engagement.findUnique({ where: { id: req.params.id } });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "engagement",
    resourceId: engagement.id,
    engagementId: engagement.id,
    result: "SUCCESS",
  });

  const { assumptionsEnc, exclusionsEnc, ...rest } = engagement;
  const assumptions = assumptionsEnc
    ? await decryptField(kms, assumptionsEnc as any, `engagement:assumptions`)
    : undefined;
  const exclusions = exclusionsEnc
    ? await decryptField(kms, exclusionsEnc as any, `engagement:exclusions`)
    : undefined;

  res.json({ ...rest, assumptions, exclusions });
});

const scopeSchema = z.object({
  assumptions: z.string().max(10_000).optional(),
  exclusions: z.string().max(10_000).optional(),
  status: z.enum(["SCOPING", "ACTIVE", "REPORTING", "RETEST", "CLOSED"]).optional(),
});

engagementsRouter.patch(
  "/:id/scope",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = scopeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { assumptions, exclusions, status } = parsed.data;

    const updated = await prisma.engagement.update({
      where: { id: req.params.id },
      data: {
        status,
        assumptionsEnc: assumptions
          ? ((await encryptField(kms, assumptions, `engagement:assumptions`)) as any)
          : undefined,
        exclusionsEnc: exclusions
          ? ((await encryptField(kms, exclusions, `engagement:exclusions`)) as any)
          : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "engagement",
      resourceId: updated.id,
      engagementId: updated.id,
      result: "SUCCESS",
    });

    res.json(updated);
  }
);

// Hard gate: no test (and by extension no finding) can exist on an engagement
// until it has been explicitly authorized. This mirrors the rule that
// unauthorized testing is never acceptable, enforced in code, not just process.
const authorizeSchema = z.object({
  authorizedBy: z.string().trim().min(1).max(200),
  authorizationDocRef: z.string().min(1).max(500), // object storage key of the signed scope/ROE doc
});

engagementsRouter.post(
  "/:id/authorize",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = authorizeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const updated = await prisma.engagement.update({
      where: { id: req.params.id },
      data: {
        authorizedBy: parsed.data.authorizedBy,
        authorizationDocRef: parsed.data.authorizationDocRef,
        authorizationSignedAt: new Date(),
        authorizationMethod: "MANUAL",
        status: "ACTIVE",
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "engagement.authorization",
      resourceId: updated.id,
      engagementId: updated.id,
      result: "SUCCESS",
    });

    res.json(updated);
  }
);

// --- E-signature authorization -----------------------------------------
// An alternative to the manual route above: instead of a security_admin
// self-attesting "yes, this was signed," the ROE gets sent through a real
// e-signature provider and the gate only opens once that provider itself
// confirms it's signed (checkStatus below) — verified, not self-attested.
// Falls back cleanly to a 501 when no provider is configured; the manual
// route keeps working regardless.

const sendForSignatureSchema = z.object({
  signerEmail: z.string().trim().toLowerCase().email().max(254),
  signerName: z.string().trim().min(1).max(200),
});

engagementsRouter.post(
  "/:id/authorize/send",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  sideEffectLimiter,
  uploadRoeDoc.single("file"),
  async (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: "Missing file field (the ROE/authorization PDF to send for signature)" });
      return;
    }
    const parsed = sendForSignatureSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const engagement = await prisma.engagement.findUnique({ where: { id: req.params.id } });
    if (!engagement) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    let result;
    try {
      result = await esignature.sendForSignature({
        documentBuffer: req.file.buffer,
        documentName: req.file.originalname,
        signerEmail: parsed.data.signerEmail,
        signerName: parsed.data.signerName,
        externalId: engagement.id,
      });
    } catch (err) {
      res.status(502).json({ error: err instanceof Error ? err.message : "E-signature provider request failed" });
      return;
    }

    const updated = await prisma.engagement.update({
      where: { id: engagement.id },
      data: {
        authorizedBy: parsed.data.signerName,
        authorizationMethod: "ESIGNATURE",
        authorizationEnvelopeId: result.envelopeId,
        authorizationRequestStatus: "SENT",
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "engagement.authorization.esignature",
      resourceId: engagement.id,
      engagementId: engagement.id,
      result: "SUCCESS",
    });

    res.status(201).json({
      envelopeId: result.envelopeId,
      signingUrl: result.signingUrl,
      status: updated.authorizationRequestStatus,
    });
  }
);

engagementsRouter.post(
  "/:id/authorize/check",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const engagement = await prisma.engagement.findUnique({ where: { id: req.params.id } });
    if (!engagement) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    if (!engagement.authorizationEnvelopeId) {
      res.status(400).json({ error: "No e-signature request has been sent for this engagement yet — call authorize/send first." });
      return;
    }

    let result;
    try {
      result = await esignature.checkStatus(engagement.authorizationEnvelopeId);
    } catch (err) {
      res.status(502).json({ error: err instanceof Error ? err.message : "E-signature provider status check failed" });
      return;
    }

    const alreadySigned = Boolean(engagement.authorizationSignedAt);
    const justSigned = result.status === "SIGNED" && !alreadySigned;

    // Best-effort: fetch and encrypt-store the actual signed PDF, not just
    // proof-it-happened metadata — a client or their lawyer may reasonably
    // want the signed artifact itself retrievable, not just an envelope ID.
    // Never blocks the authorization confirmation on failure here — the
    // verified signature (envelope ID + provider-confirmed signedAt) is
    // what actually gates testing; the stored copy is additive.
    let signedDocFields: Record<string, unknown> = {};
    if (justSigned) {
      try {
        const pdfBuffer = await esignature.getSignedDocument(engagement.authorizationEnvelopeId);
        if (pdfBuffer) {
          const encrypted = await encryptBuffer(kms, pdfBuffer, `authorization-doc:${engagement.id}`);
          const storageKey = newStorageKey(`authorization-docs/${engagement.id}`);
          await objectStorage.put(storageKey, encrypted.ciphertext);
          signedDocFields = {
            authorizationDocRef: storageKey,
            authorizationDocIv: encrypted.iv,
            authorizationDocAuthTag: encrypted.authTag,
            authorizationDocEncryptedDataKey: encrypted.encryptedDataKey,
            authorizationDocKmsKeyId: encrypted.kmsKeyId,
            authorizationDocKeyVersion: encrypted.keyVersion,
          };
        }
      } catch (err) {
        logger.error({ err, engagementId: engagement.id }, "Failed to fetch/store the signed authorization PDF");
      }
    }

    const updated = await prisma.engagement.update({
      where: { id: engagement.id },
      data: {
        authorizationRequestStatus: result.status,
        ...(justSigned ? { authorizationSignedAt: result.signedAt ?? new Date(), status: "ACTIVE", ...signedDocFields } : {}),
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "engagement.authorization.esignature",
      resourceId: engagement.id,
      engagementId: engagement.id,
      result: "SUCCESS",
    });

    res.json({
      status: updated.authorizationRequestStatus,
      authorized: Boolean(updated.authorizationSignedAt),
      authorizationSignedAt: updated.authorizationSignedAt,
    });
  }
);

// The actual signed document — only populated by the e-signature path
// (authorize/check, above) once a provider confirms it's signed and
// getSignedDocument() successfully fetched it; the manual path only ever
// has a free-text reference, nothing stored here to serve. Open to every
// org role, not just security_admin/technical — it's the client's own
// signed contract, not sensitive exploitation evidence.
engagementsRouter.get("/:id/authorization-document", requireAuth, async (req, res) => {
  const engagement = await prisma.engagement.findUnique({ where: { id: req.params.id } });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  if (!engagement.authorizationDocRef || !engagement.authorizationDocIv) {
    res.status(404).json({ error: "No stored signed document for this engagement (manual authorization, or the fetch failed — check authorizationDocRef)" });
    return;
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DOWNLOAD",
    resourceType: "engagement.authorizationDocument",
    resourceId: engagement.id,
    engagementId: engagement.id,
    result: "SUCCESS",
  });

  const ciphertext = await objectStorage.get(engagement.authorizationDocRef);
  const plaintext = await decryptBuffer(
    kms,
    {
      ciphertext,
      iv: engagement.authorizationDocIv,
      authTag: engagement.authorizationDocAuthTag!,
      encryptedDataKey: engagement.authorizationDocEncryptedDataKey!,
      kmsKeyId: engagement.authorizationDocKmsKeyId!,
    },
    `authorization-doc:${engagement.id}`
  );

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="authorization-${engagement.id}.pdf"`);
  res.send(plaintext);
});

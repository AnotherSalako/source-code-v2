import { Request, Router } from "express";
import { z } from "zod";
import { AssetType, Criticality } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { checkDnsTxt, checkHttpFile, generateVerificationToken, WELL_KNOWN_PATH } from "./verification";

export const assetsRouter = Router({ mergeParams: true });

const createSchema = z.object({
  type: z.nativeEnum(AssetType),
  name: z.string().trim().min(1).max(200),
  identifier: z.string().trim().min(1).max(500), // IP/hostname/URL — encrypted
  owner: z.string().trim().max(200).optional(),
  criticality: z.nativeEnum(Criticality).optional(),
  inScope: z.boolean().optional(),
  notes: z.string().max(10_000).optional(),
});

assetsRouter.post(
  "/engagements/:engagementId/assets",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId } = req.params;
    const { type, name, identifier, owner, criticality, inScope, notes } = parsed.data;

    const asset = await prisma.asset.create({
      data: {
        engagementId,
        type,
        name,
        owner,
        criticality,
        inScope: inScope ?? true,
        identifierEnc: (await encryptField(kms, identifier, `asset:identifier`)) as any,
        notesEnc: notes ? ((await encryptField(kms, notes, `asset:notes`)) as any) : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "asset",
      resourceId: asset.id,
      engagementId,
      result: "SUCCESS",
    });

    res.status(201).json({ id: asset.id, type: asset.type, name: asset.name });
  }
);

assetsRouter.get("/engagements/:engagementId/assets", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const assets = await prisma.asset.findMany({ where: { engagementId } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "asset",
    resourceId: null,
    engagementId,
    result: "SUCCESS",
  });

  const decorated = await Promise.all(
    assets.map(async (asset) => ({
      id: asset.id,
      type: asset.type,
      name: asset.name,
      criticality: asset.criticality,
      inScope: asset.inScope,
      identifier: await decryptField(kms, asset.identifierEnc as any, `asset:identifier`),
      verificationStatus: asset.verificationStatus,
      verificationMethod: asset.verificationMethod,
      verifiedAt: asset.verifiedAt,
    }))
  );

  res.json(decorated);
});

// --- Ownership verification -------------------------------------------------
// An automated scan (src/modules/scanning) refuses to run against a WEB/API
// asset until its verificationStatus is VERIFIED. This proves whoever
// requested the scan actually controls the target — otherwise "scan this
// URL" is an open SSRF/abuse primitive against literally any site on the
// internet, authorized or not.

async function loadOwnedAsset(req: Request, assetId: string, engagementId: string) {
  const asset = await prisma.asset.findUnique({ where: { id: assetId }, include: { engagement: true } });
  if (!asset || asset.engagementId !== engagementId) return null;
  if (!assertOwnOrg(req, asset.engagement.clientId)) return null;
  return asset;
}

const startVerificationSchema = z.object({
  method: z.enum(["DNS_TXT", "HTTP_FILE"]),
});

assetsRouter.post(
  "/engagements/:engagementId/assets/:assetId/verification/start",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = startVerificationSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId, assetId } = req.params;
    const asset = await loadOwnedAsset(req, assetId, engagementId);
    if (!asset) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const token = generateVerificationToken();
    await prisma.asset.update({
      where: { id: assetId },
      data: {
        verificationMethod: parsed.data.method,
        verificationStatus: "PENDING",
        verificationToken: token,
        verifiedAt: null,
        verifiedBy: null,
      },
    });

    const identifier = await decryptField(kms, asset.identifierEnc as any, `asset:identifier`);
    const instructions =
      parsed.data.method === "DNS_TXT"
        ? `Create a TXT record on ${identifier} (or its apex domain) with this exact value: ${token}`
        : `Publish a file at ${identifier}${WELL_KNOWN_PATH} whose exact contents (nothing else) are: ${token}`;

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "asset.verification.start",
      resourceId: assetId,
      engagementId,
      result: "SUCCESS",
    });

    res.json({ method: parsed.data.method, token, instructions });
  }
);

assetsRouter.post(
  "/engagements/:engagementId/assets/:assetId/verification/check",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const { engagementId, assetId } = req.params;
    const asset = await loadOwnedAsset(req, assetId, engagementId);
    if (!asset) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    if (!asset.verificationMethod || !asset.verificationToken || asset.verificationMethod === "MANUAL") {
      res.status(400).json({ error: "No DNS/HTTP verification in progress — call verification/start first" });
      return;
    }

    const identifier = await decryptField(kms, asset.identifierEnc as any, `asset:identifier`);
    let verified: boolean;
    try {
      if (asset.verificationMethod === "DNS_TXT") {
        const hostname = identifier.includes("://") ? new URL(identifier).hostname : identifier;
        verified = await checkDnsTxt(hostname, asset.verificationToken);
      } else {
        const base = identifier.includes("://") ? identifier : `https://${identifier}`;
        verified = await checkHttpFile(base, asset.verificationToken);
      }
    } catch {
      verified = false;
    }

    if (verified) {
      await prisma.asset.update({
        where: { id: assetId },
        data: { verificationStatus: "VERIFIED", verifiedAt: new Date(), verifiedBy: req.user!.id },
      });
    }

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "asset.verification.check",
      resourceId: assetId,
      engagementId,
      result: verified ? "SUCCESS" : "DENIED",
    });

    res.json({ verified });
  }
);

const manualVerificationSchema = z.object({
  justification: z
    .string()
    .min(10, "Explain why this asset is authorized without DNS/HTTP proof (e.g. reference to the signed ROE/SOW).")
    .max(2_000),
});

assetsRouter.post(
  "/engagements/:engagementId/assets/:assetId/verification/manual",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = manualVerificationSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId, assetId } = req.params;
    const asset = await loadOwnedAsset(req, assetId, engagementId);
    if (!asset) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    await prisma.asset.update({
      where: { id: assetId },
      data: {
        verificationMethod: "MANUAL",
        verificationStatus: "VERIFIED",
        verificationToken: parsed.data.justification, // MANUAL repurposes this field as the recorded justification, not a secret
        verifiedAt: new Date(),
        verifiedBy: req.user!.id,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "asset.verification.manual",
      resourceId: assetId,
      engagementId,
      result: "SUCCESS",
    });

    res.json({ verified: true });
  }
);

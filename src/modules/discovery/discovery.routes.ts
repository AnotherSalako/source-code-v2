import { Router } from "express";
import { AssetType, Criticality } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { sideEffectLimiter } from "../../middleware/rate-limit";
import { startDiscovery } from "./discovery-runner";

export const discoveryRouter = Router({ mergeParams: true });

// Same set scanning restricts to — discovery needs a hostname-shaped
// identifier to query certificate-transparency logs against.
const DISCOVERABLE_TYPES = new Set(["WEB", "API"]);

discoveryRouter.post(
  "/engagements/:engagementId/assets/:assetId/discover",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  sideEffectLimiter,
  async (req, res) => {
    const { engagementId, assetId } = req.params;

    const asset = await prisma.asset.findUnique({ where: { id: assetId }, include: { engagement: true } });
    if (!asset || asset.engagementId !== engagementId || !assertOwnOrg(req, asset.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    if (!asset.engagement.authorizationSignedAt) {
      res.status(403).json({ error: "This engagement has no signed authorization on file yet — cannot run discovery" });
      return;
    }
    if (!asset.inScope) {
      res.status(403).json({ error: "This asset is marked out of scope" });
      return;
    }
    if (!DISCOVERABLE_TYPES.has(asset.type)) {
      res.status(400).json({ error: `Attack-surface discovery supports WEB/API assets, not ${asset.type}` });
      return;
    }
    // Same ownership gate scanning uses, and for the same reason: querying
    // CT logs and connect-probing whatever resolves is still directed at a
    // target, so "prove you control the root domain first" is what keeps
    // this from being an open abuse primitive against any domain at all.
    if (asset.verificationStatus !== "VERIFIED") {
      res.status(403).json({
        error: "This asset hasn't proven ownership yet — run verification/start then verification/check (or verification/manual) first",
      });
      return;
    }

    const alreadyRunning = await prisma.discoveryJob.findFirst({
      where: { assetId, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (alreadyRunning) {
      res.status(409).json({ error: "A discovery run is already in progress for this asset", discoveryJobId: alreadyRunning.id });
      return;
    }

    const { discoveryJobId } = await startDiscovery({ engagementId, assetId, triggeredById: req.user!.id });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "discoveryJob",
      resourceId: discoveryJobId,
      engagementId,
      result: "SUCCESS",
    });

    res.status(202).json({ discoveryJobId, status: "QUEUED" });
  }
);

discoveryRouter.get("/engagements/:engagementId/discovery-jobs", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, select: { clientId: true } });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const jobs = await prisma.discoveryJob.findMany({
    where: { engagementId },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      assetId: true,
      tool: true,
      status: true,
      startedAt: true,
      completedAt: true,
      errorMessage: true,
      discoveredCount: true,
      createdAt: true,
    },
  });

  res.json(jobs);
});

discoveryRouter.get("/engagements/:engagementId/discovered-assets", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, select: { clientId: true } });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const rows = await prisma.discoveredAsset.findMany({ where: { engagementId }, orderBy: { createdAt: "desc" } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "discoveredAsset",
    resourceId: null,
    engagementId,
    result: "SUCCESS",
  });

  const decorated = await Promise.all(
    rows.map(async (row) => ({
      id: row.id,
      parentAssetId: row.parentAssetId,
      discoveryJobId: row.discoveryJobId,
      value: await decryptField(kms, row.valueEnc as any, `discoveredAsset:value`),
      source: row.source,
      openPorts: row.openPorts,
      status: row.status,
      promotedAssetId: row.promotedAssetId,
      reviewedBy: row.reviewedBy,
      reviewedAt: row.reviewedAt,
      createdAt: row.createdAt,
    }))
  );

  res.json(decorated);
});

async function loadOwnedDiscoveredAsset(req: import("express").Request, id: string) {
  const row = await prisma.discoveredAsset.findUnique({ where: { id }, include: { engagement: true } });
  if (!row || !assertOwnOrg(req, row.engagement.clientId)) return null;
  return row;
}

// Promoting turns a candidate into a real Asset — but a human-reviewed
// candidate is not the same thing as a human-verified owner. The new Asset
// starts UNVERIFIED and has to pass the exact same DNS/HTTP ownership
// verification any manually-added asset does before it can be scanned;
// promotion only ever expands what's tracked, never what's actionable.
discoveryRouter.post(
  "/discovered-assets/:id/promote",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const row = await loadOwnedDiscoveredAsset(req, req.params.id);
    if (!row) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    if (row.status !== "NEW") {
      res.status(400).json({ error: `Already reviewed (status: ${row.status})` });
      return;
    }

    const value = await decryptField(kms, row.valueEnc as any, `discoveredAsset:value`);

    const asset = await prisma.asset.create({
      data: {
        engagementId: row.engagementId,
        type: AssetType.WEB,
        name: value,
        criticality: Criticality.MEDIUM,
        inScope: true,
        identifierEnc: (await encryptField(kms, value, `asset:identifier`)) as any,
      },
    });

    await prisma.discoveredAsset.update({
      where: { id: row.id },
      data: { status: "PROMOTED", promotedAssetId: asset.id, reviewedBy: req.user!.id, reviewedAt: new Date() },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "asset.promotedFromDiscovery",
      resourceId: asset.id,
      engagementId: row.engagementId,
      result: "SUCCESS",
    });

    res.status(201).json({ id: asset.id, type: asset.type, name: asset.name });
  }
);

discoveryRouter.post(
  "/discovered-assets/:id/ignore",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const row = await loadOwnedDiscoveredAsset(req, req.params.id);
    if (!row) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    if (row.status !== "NEW") {
      res.status(400).json({ error: `Already reviewed (status: ${row.status})` });
      return;
    }

    await prisma.discoveredAsset.update({
      where: { id: row.id },
      data: { status: "IGNORED", reviewedBy: req.user!.id, reviewedAt: new Date() },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "discoveredAsset.ignore",
      resourceId: row.id,
      engagementId: row.engagementId,
      result: "SUCCESS",
    });

    res.json({ status: "IGNORED" });
  }
);

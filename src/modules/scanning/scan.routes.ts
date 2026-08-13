import { Router } from "express";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { startScan } from "./scan-runner";
import { sideEffectLimiter } from "../../middleware/rate-limit";

export const scanRouter = Router({ mergeParams: true });

const SCANNABLE_TYPES = new Set(["WEB", "API"]);

scanRouter.post(
  "/engagements/:engagementId/assets/:assetId/scan",
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
      res.status(403).json({ error: "This engagement has no signed authorization on file yet — cannot scan" });
      return;
    }
    if (!asset.inScope) {
      res.status(403).json({ error: "This asset is marked out of scope" });
      return;
    }
    if (!SCANNABLE_TYPES.has(asset.type)) {
      res.status(400).json({ error: `Automated scanning supports WEB/API assets, not ${asset.type}` });
      return;
    }
    if (asset.verificationStatus !== "VERIFIED") {
      res.status(403).json({
        error: "This asset hasn't proven ownership yet — run verification/start then verification/check (or verification/manual) first",
      });
      return;
    }

    const alreadyRunning = await prisma.scanJob.findFirst({
      where: { assetId, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (alreadyRunning) {
      res.status(409).json({ error: "A scan is already in progress for this asset", scanJobId: alreadyRunning.id });
      return;
    }

    const { scanJobId, testId } = await startScan({
      engagementId,
      assetId,
      methodology: "Automated (in-app, Nuclei — non-intrusive template set)",
      triggeredById: req.user!.id,
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "scanJob",
      resourceId: scanJobId,
      engagementId,
      result: "SUCCESS",
    });

    res.status(202).json({ scanJobId, testId, status: "QUEUED" });
  }
);

scanRouter.get("/engagements/:engagementId/scan-jobs", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, select: { clientId: true } });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const jobs = await prisma.scanJob.findMany({
    where: { engagementId },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      assetId: true,
      testId: true,
      tool: true,
      status: true,
      startedAt: true,
      completedAt: true,
      errorMessage: true,
      findingsCreated: true,
      findingsSkipped: true,
      createdAt: true,
    },
  });

  res.json(jobs);
});

scanRouter.get("/scan-jobs/:id", requireAuth, async (req, res) => {
  const job = await prisma.scanJob.findUnique({
    where: { id: req.params.id },
    include: { engagement: { select: { clientId: true } } },
  });
  if (!job || !assertOwnOrg(req, job.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const base = {
    id: job.id,
    assetId: job.assetId,
    testId: job.testId,
    tool: job.tool,
    status: job.status,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
    errorMessage: job.errorMessage,
    findingsCreated: job.findingsCreated,
    findingsSkipped: job.findingsSkipped,
    createdAt: job.createdAt,
  };

  // Raw scanner output can include full request/response headers and
  // server details — same sensitivity tier as evidence, so it's withheld
  // from exec_client and technical_client the way evidence downloads are.
  if (req.user!.role !== "SECURITY_ADMIN" || !job.rawResultEnc) {
    res.json(base);
    return;
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DECRYPT",
    resourceType: "scanJob.rawResult",
    resourceId: job.id,
    engagementId: job.engagementId,
    result: "SUCCESS",
  });

  const rawResult = await decryptField(kms, job.rawResultEnc as any, `scanjob:rawResult`);
  res.json({ ...base, rawResult });
});

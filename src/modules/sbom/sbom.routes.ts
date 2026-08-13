import { Router } from "express";
import multer from "multer";
import { prisma } from "../../db/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { sideEffectLimiter } from "../../middleware/rate-limit";
import { writeAuditLog } from "../audit/audit.service";
import { parseNpmLockfile } from "./sbom-parser";
import { findVulnerabilities } from "./osv-client";

export const sbomRouter = Router({ mergeParams: true });

// Same in-memory-buffer reasoning as evidence uploads — a lockfile is text,
// not a multi-GB binary; 10MB comfortably covers even a very large
// monorepo's package-lock.json.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// Computed on demand, like /findings/clusters, /attack-paths, and CSPM's
// scan route — nothing here is auto-created as a Finding. An SbomIssue
// (real vulnerability data from OSV.dev, but about a *dependency*, not
// something this app's own testing found) doesn't fit Finding's
// pentest-workflow shape any more than a WatchAlert or CspmIssue does; a
// human reviewing the results decides what, if anything, becomes a
// tracked Finding.
sbomRouter.post(
  "/engagements/:engagementId/assets/:assetId/sbom-scan",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  sideEffectLimiter,
  upload.single("file"),
  async (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: "Missing file field — upload a package-lock.json" });
      return;
    }
    const { engagementId, assetId } = req.params;

    const asset = await prisma.asset.findUnique({ where: { id: assetId }, include: { engagement: true } });
    if (!asset || asset.engagementId !== engagementId || !assertOwnOrg(req, asset.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    let deps;
    try {
      deps = parseNpmLockfile(req.file.buffer.toString("utf8"));
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : "Could not parse the uploaded file" });
      return;
    }
    if (deps.length === 0) {
      res.json({ dependencyCount: 0, issues: [] });
      return;
    }

    const issues = await findVulnerabilities(deps);

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "VIEW",
      resourceType: "asset.sbomScan",
      resourceId: assetId,
      engagementId,
      result: "SUCCESS",
    });

    res.json({ dependencyCount: deps.length, issues });
  }
);

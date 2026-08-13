import { Router } from "express";
import { prisma } from "../../db/prisma";
import { env } from "../../config/env";
import { logger } from "../../config/logger";
import { writeAuditLog } from "../audit/audit.service";
import { startScan } from "../scanning/scan-runner";
import { notifySweepHeartbeat } from "../../notifications";

export const internalScheduledScansRouter = Router();

// Cap per invocation, not per day — this endpoint has no concept of "once a
// day," it just does whatever's due every time Vercel Cron calls it. A low
// cap keeps one run from kicking off a pile of concurrent Nuclei processes
// if a lot of assets are eligible at once; anything left over just gets
// picked up on the next scheduled run instead.
const MAX_SCANS_PER_RUN = 5;

// Same pattern as /internal/rotate-keys: called on a schedule (see
// vercel.json "crons"), never by a browser, protected by CRON_SECRET rather
// than requireAuth since there's no logged-in user in a cron context.
//
// This only ever *starts* scans — results land as ordinary Findings for a
// human to review in the dashboard, same as a manually-triggered scan.
// Nothing about this generates or sends a report; that stays a separate,
// explicit, human-triggered action (POST /engagements/:id/reports/generate).
// "Automated scanning" and "a human reviews before anything reaches the
// client" are two different gates, and this only ever touches the first one.
internalScheduledScansRouter.get("/internal/scheduled-scans", async (req, res) => {
  if (!env.cronSecret) {
    res.status(503).json({ error: "Scheduled scanning is not configured (CRON_SECRET unset)" });
    return;
  }
  if (req.headers.authorization !== `Bearer ${env.cronSecret}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const eligibleAssets = await prisma.asset.findMany({
    where: {
      inScope: true,
      type: { in: ["WEB", "API"] },
      verificationStatus: "VERIFIED",
      engagement: { status: "ACTIVE", authorizationSignedAt: { not: null } },
    },
    select: { id: true, engagementId: true },
  });

  const started: { assetId: string; scanJobId: string; testId: string }[] = [];
  const skipped: { assetId: string; reason: string }[] = [];

  for (const asset of eligibleAssets) {
    if (started.length >= MAX_SCANS_PER_RUN) {
      skipped.push({ assetId: asset.id, reason: `Per-run cap (${MAX_SCANS_PER_RUN}) reached — will be picked up next run` });
      continue;
    }

    const alreadyRunning = await prisma.scanJob.findFirst({
      where: { assetId: asset.id, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (alreadyRunning) {
      skipped.push({ assetId: asset.id, reason: "Already has a scan in progress" });
      continue;
    }

    const { scanJobId, testId } = await startScan({
      engagementId: asset.engagementId,
      assetId: asset.id,
      methodology: "Automated (scheduled, Nuclei — non-intrusive template set)",
      triggeredById: "system:scheduled-cron",
    });

    await writeAuditLog(prisma, {
      userId: null,
      action: "CREATE",
      resourceType: "scanJob.scheduled",
      resourceId: scanJobId,
      engagementId: asset.engagementId,
      result: "SUCCESS",
    });

    started.push({ assetId: asset.id, scanJobId, testId });
  }

  logger.info({ started: started.length, skipped: skipped.length }, "Scheduled scan sweep complete");

  void notifySweepHeartbeat({
    eligibleCount: eligibleAssets.length,
    startedCount: started.length,
    skippedCount: skipped.length,
    timestamp: new Date(),
  }); // fire-and-forget — never blocks the cron response on a flaky webhook/email API

  res.json({ started, skipped });
});

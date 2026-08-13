import { Router } from "express";
import { prisma } from "../../db/prisma";
import { env } from "../../config/env";
import { logger } from "../../config/logger";
import { writeAuditLog } from "../audit/audit.service";
import { startWatchCycle } from "../discovery/watch-runner";

export const internalScheduledWatchRouter = Router();

// Same per-invocation cap reasoning as scheduled-scans.routes.ts: a watch
// cycle does real work (an nmap pass per already-known asset, plus a fresh
// crt.sh sweep), so a low cap keeps one cron tick from firing a pile of
// concurrent scans if a lot of assets are eligible at once. Leftovers are
// picked up on the next scheduled run, not lost.
const MAX_WATCH_CYCLES_PER_RUN = 5;

// Same pattern as /internal/scheduled-scans: called on a schedule (see
// vercel.json "crons"), never by a browser, protected by CRON_SECRET rather
// than requireAuth since there's no logged-in user in a cron context.
//
// Eligibility mirrors scheduled-scans exactly (inScope, WEB/API, VERIFIED,
// authorized ACTIVE engagement) — watch mode re-checks the same assets
// scheduled scanning already covers, just for attack-surface drift instead
// of new Nuclei findings. Nothing here promotes a DiscoveredAsset or
// creates a Finding on its own; it only ever writes WatchAlert rows for a
// human to review, same "automated detection, human-gated action" split
// scheduled-scans already draws for Findings.
internalScheduledWatchRouter.get("/internal/scheduled-watch", async (req, res) => {
  if (!env.cronSecret) {
    res.status(503).json({ error: "Scheduled watch mode is not configured (CRON_SECRET unset)" });
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

  const started: { assetId: string; discoveryJobId: string }[] = [];
  const skipped: { assetId: string; reason: string }[] = [];

  for (const asset of eligibleAssets) {
    if (started.length >= MAX_WATCH_CYCLES_PER_RUN) {
      skipped.push({ assetId: asset.id, reason: `Per-run cap (${MAX_WATCH_CYCLES_PER_RUN}) reached — will be picked up next run` });
      continue;
    }

    const alreadyRunning = await prisma.discoveryJob.findFirst({
      where: { assetId: asset.id, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (alreadyRunning) {
      skipped.push({ assetId: asset.id, reason: "Already has a discovery/watch run in progress" });
      continue;
    }

    // Same fire-and-forget shape as startScan()/startDiscovery(): this
    // resolves as soon as the DiscoveryJob row exists, not when the cycle
    // finishes — awaiting up to MAX_WATCH_CYCLES_PER_RUN full cycles here
    // (each up to MAX_RUNTIME_MS) would risk this cron invocation itself
    // timing out.
    const { discoveryJobId } = await startWatchCycle({
      engagementId: asset.engagementId,
      assetId: asset.id,
      triggeredById: "system:scheduled-watch",
    });

    await writeAuditLog(prisma, {
      userId: null,
      action: "CREATE",
      resourceType: "discoveryJob.watch",
      resourceId: discoveryJobId,
      engagementId: asset.engagementId,
      result: "SUCCESS",
    });

    started.push({ assetId: asset.id, discoveryJobId });
  }

  logger.info({ started: started.length, skipped: skipped.length }, "Scheduled watch sweep complete");

  res.json({ started, skipped });
});

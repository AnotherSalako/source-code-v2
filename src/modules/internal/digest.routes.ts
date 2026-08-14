import { Router } from "express";
import { env } from "../../config/env";
import { buildWeeklyDigest } from "./digest.service";
import { notifyWeeklyDigest } from "../../notifications";

export const internalDigestRouter = Router();

// Same pattern as every other /internal/* cron route: called on a schedule
// (see vercel.json "crons"), never by a browser, protected by CRON_SECRET
// rather than requireAuth since there's no logged-in user in a cron
// context. No-ops cleanly if no notifier (Slack/email) is configured —
// same as notifySweepHeartbeat — rather than needing its own separate
// "is anyone listening" check here.
internalDigestRouter.get("/internal/weekly-digest", async (req, res) => {
  if (!env.cronSecret) {
    res.status(503).json({ error: "Scheduled digests are not configured (CRON_SECRET unset)" });
    return;
  }
  if (req.headers.authorization !== `Bearer ${env.cronSecret}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const digest = await buildWeeklyDigest();
  await notifyWeeklyDigest(digest);

  res.json(digest);
});

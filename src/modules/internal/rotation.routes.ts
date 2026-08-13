import { Router } from "express";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { env } from "../../config/env";
import { rotateAllFields } from "../../crypto/rotation";
import { logger } from "../../config/logger";

export const internalRotationRouter = Router();

// Called on a schedule (see vercel.json "crons"), never by a browser — not
// mounted behind requireAuth/JWT since there's no logged-in user in a cron
// context. GET, not POST: Vercel's Cron Jobs invoke via GET, and
// automatically send `Authorization: Bearer $CRON_SECRET` when a project env
// var of that exact name is set — matching that convention here means it
// works with zero extra configuration beyond setting CRON_SECRET and the
// vercel.json entry. Refuses every request if CRON_SECRET isn't configured,
// rather than defaulting open.
internalRotationRouter.get("/internal/rotate-keys", async (req, res) => {
  if (!env.cronSecret) {
    res.status(503).json({ error: "Key rotation is not configured (CRON_SECRET unset)" });
    return;
  }
  if (req.headers.authorization !== `Bearer ${env.cronSecret}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const results = await rotateAllFields(prisma, kms);
  const totalRotated = results.reduce((sum, r) => sum + r.rotated, 0);
  logger.info({ results, totalRotated }, "Key rotation sweep complete");

  res.json({ totalRotated, results });
});

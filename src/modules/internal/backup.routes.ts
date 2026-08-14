import { Router } from "express";
import { env } from "../../config/env";
import { logger } from "../../config/logger";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";
import { runDatabaseBackup, listBackups } from "./backup.service";

export const internalBackupRouter = Router();

// Same pattern as /internal/rotate-keys and /internal/scheduled-scans:
// called on a schedule (see vercel.json "crons"), never by a browser,
// protected by CRON_SECRET rather than requireAuth since there's no
// logged-in user in a cron context.
internalBackupRouter.get("/internal/scheduled-backup", async (req, res) => {
  if (!env.cronSecret) {
    res.status(503).json({ error: "Scheduled backups are not configured (CRON_SECRET unset)" });
    return;
  }
  if (req.headers.authorization !== `Bearer ${env.cronSecret}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const summary = await runDatabaseBackup();
    res.json(summary);
  } catch (err) {
    logger.error({ err }, "Scheduled database backup failed");
    res.status(500).json({ error: "Backup failed" });
  }
});

// Lets a SECURITY_ADMIN confirm from the app itself that backups are
// actually running, without needing direct DB access — metadata only
// (id/size/table row counts/timestamp), never the ciphertext or its
// decryption key, both of which stay in object storage / the DatabaseBackup
// row respectively and are only ever read by scripts/restore-backup.ts.
internalBackupRouter.get("/internal/backups", requireAuth, requireRole("SECURITY_ADMIN"), async (_req, res) => {
  const backups = await listBackups();
  res.json({ backups });
});

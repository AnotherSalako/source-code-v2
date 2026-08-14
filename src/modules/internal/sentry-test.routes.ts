import { Router } from "express";
import { env } from "../../config/env";

export const internalSentryTestRouter = Router();

// A deliberate way to answer "is error tracking actually alive right now,"
// the same reasoning as the scheduled-scan sweep's heartbeat notification —
// staying quiet is ambiguous (all clear, or silently broken since the DSN
// rotated), so this exists to make a real, findable event on demand rather
// than waiting to discover a gap during a real incident. CRON_SECRET-gated
// like every other /internal/* route, not public — this is an operator
// tool, not something meant to be triggerable by anyone who finds the URL.
internalSentryTestRouter.get("/internal/sentry-test", (req, res) => {
  if (!env.cronSecret) {
    res.status(503).json({ error: "Not configured (CRON_SECRET unset)" });
    return;
  }
  if (req.headers.authorization !== `Bearer ${env.cronSecret}`) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  const marker = `sentry-test-${Date.now()}`;
  // Thrown, not just captureException()'d directly — this exercises the
  // real path a genuine unhandled error takes (express-async-errors ->
  // app.ts's global error handler -> captureException), not a shortcut
  // around it.
  throw new Error(`Deliberate Sentry test event [${marker}] — search Sentry for this marker to confirm delivery.`);
});

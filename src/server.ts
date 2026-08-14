// initSentry() now runs inside createApp() itself (see app.ts) so it fires
// for both this long-running entry point and the Vercel serverless one
// (api/index.ts), which never executes this file.
import { captureException } from "./config/sentry";
import { createApp } from "./app";
import { env } from "./config/env";
import { logger } from "./config/logger";
import { prisma } from "./db/prisma";

// Last-resort net for rejections/exceptions outside the request lifecycle
// (express-async-errors covers everything inside it). Log and keep serving —
// a security-assessment API staying up through a transient error is better
// than every client-facing request dying with it.
process.on("unhandledRejection", (reason) => {
  logger.error({ reason }, "Unhandled rejection");
  void captureException(reason);
});
process.on("uncaughtException", (err) => {
  logger.error({ err }, "Uncaught exception");
  void captureException(err);
});

// A ScanJob's QUEUED/RUNNING state is only ever advanced by this same
// process (src/modules/scanning/scan-runner.ts) — there's no separate
// worker or queue. If the process dies or restarts mid-scan, that job would
// otherwise sit RUNNING forever, which also permanently blocks re-scanning
// that asset (scan.routes.ts refuses a second scan while one is "in
// progress"). Sweep them at boot rather than adding a timeout-based check
// to every read path.
async function failOrphanedScanJobs(): Promise<void> {
  const { count } = await prisma.scanJob.updateMany({
    where: { status: { in: ["QUEUED", "RUNNING"] } },
    data: { status: "FAILED", completedAt: new Date(), errorMessage: "Interrupted by a server restart" },
  });
  if (count > 0) logger.warn({ count }, "Marked orphaned scan job(s) as FAILED on startup");
}

// Same failure mode as failOrphanedScanJobs above, same fix — a DiscoveryJob
// is only ever advanced by this process (discovery-runner.ts), so a restart
// mid-run would otherwise leave it RUNNING forever and permanently block
// re-running discovery on that asset (discovery.routes.ts refuses a second
// run while one is "in progress").
async function failOrphanedDiscoveryJobs(): Promise<void> {
  const { count } = await prisma.discoveryJob.updateMany({
    where: { status: { in: ["QUEUED", "RUNNING"] } },
    data: { status: "FAILED", completedAt: new Date(), errorMessage: "Interrupted by a server restart" },
  });
  if (count > 0) logger.warn({ count }, "Marked orphaned discovery job(s) as FAILED on startup");
}

const app = createApp();

Promise.all([
  failOrphanedScanJobs().catch((err) => logger.error({ err }, "Failed to sweep orphaned scan jobs on startup")),
  failOrphanedDiscoveryJobs().catch((err) => logger.error({ err }, "Failed to sweep orphaned discovery jobs on startup")),
]).finally(() => {
  app.listen(env.port, () => {
    logger.info(`Jupiter API listening on port ${env.port}`);
  });
});

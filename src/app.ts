import express from "express";
// Must be imported before any router is constructed — patches Express so
// a rejected promise inside an async route handler reaches the error
// middleware below instead of becoming an unhandled rejection that can
// crash the whole process (e.g. a transient DB/pooler hiccup used to take
// the entire API down instead of just failing that one request).
import "express-async-errors";
import cors from "cors";
import helmet from "helmet";
import pinoHttp from "pino-http";
import { clerkMiddleware } from "@clerk/express";
import "./middleware/types";
import { env } from "./config/env";
import { logger } from "./config/logger";
import { generalLimiter } from "./middleware/rate-limit";
import { initSentry, captureException } from "./config/sentry";

import { authRouter } from "./modules/auth/auth.routes";
import { usersRouter } from "./modules/users/users.routes";
import { securityRouter } from "./modules/security/security.routes";
import { clientsRouter } from "./modules/clients/clients.routes";
import { engagementsRouter } from "./modules/engagements/engagements.routes";
import { assetsRouter } from "./modules/assets/assets.routes";
import { testsRouter } from "./modules/security-tests/tests.routes";
import { findingsRouter } from "./modules/findings/findings.routes";
import { evidenceRouter } from "./modules/evidence/evidence.routes";
import { complianceRouter } from "./modules/compliance/compliance.routes";
import { reportsRouter } from "./modules/reports/reports.routes";
import { retestsRouter } from "./modules/retests/retests.routes";
import { auditRouter } from "./modules/audit/audit.routes";
import { trainingRouter } from "./modules/training/training.routes";
import { internalRotationRouter } from "./modules/internal/rotation.routes";
import { internalScheduledScansRouter } from "./modules/internal/scheduled-scans.routes";
import { internalScheduledWatchRouter } from "./modules/internal/scheduled-watch.routes";
import { internalBackupRouter } from "./modules/internal/backup.routes";
import { internalDigestRouter } from "./modules/internal/digest.routes";
import { internalSentryTestRouter } from "./modules/internal/sentry-test.routes";
import { scanRouter } from "./modules/scanning/scan.routes";
import { discoveryRouter } from "./modules/discovery/discovery.routes";
import { agentsRouter } from "./modules/agents/agents.routes";
import { cspmRouter } from "./modules/cspm/cspm.routes";
import { sbomRouter } from "./modules/sbom/sbom.routes";
import { byokRouter } from "./modules/clients/byok.routes";

export function createApp() {
  // Called here, not just in server.ts, because the Vercel serverless entry
  // point (api/index.ts) imports createApp() directly and never runs
  // server.ts at all — initSentry() living only in server.ts meant it never
  // ran in production regardless of whether SENTRY_DSN was set. Safe to call
  // on every createApp() invocation: it's a no-op when SENTRY_DSN is unset,
  // and Sentry.init() itself is idempotent (only ever called once per cold
  // start in practice, same lifecycle as the Prisma client / KMS provider
  // singletons below).
  initSentry();

  // @clerk/express reads these from process.env itself (that's the whole
  // point of the convention) rather than through this app's own env.ts — but
  // failing fast here beats Clerk's own lazy failure on first request.
  if (!process.env.CLERK_SECRET_KEY || !process.env.CLERK_PUBLISHABLE_KEY) {
    throw new Error("Missing required env var: CLERK_SECRET_KEY and/or CLERK_PUBLISHABLE_KEY");
  }

  const app = express();

  // Behind a reverse proxy (Vercel, any real deployment) req.ip would
  // otherwise resolve to the proxy's address — breaks the IP recorded in
  // audit logs. Trusting exactly one hop matches a single front-end proxy;
  // safe here since nothing else sits between clients and this app.
  app.set("trust proxy", 1);

  // TLS termination is expected to happen at the load balancer/reverse proxy
  // in front of this service; helmet still sets HSTS/other headers app-side.
  app.use(helmet());

  if (env.corsOrigins.length === 0) {
    logger.warn(
      "CORS_ORIGINS is unset — allowing all origins. Fine for local dev (the Vite proxy never " +
        "triggers cross-origin requests); set CORS_ORIGINS to the deployed frontend's URL(s) before " +
        "any real deployment goes live."
    );
    app.use(cors());
  } else {
    app.use(cors({ origin: env.corsOrigins }));
  }

  app.use(express.json({ limit: "5mb" }));
  app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === "/health" } }));
  app.use(generalLimiter);
  app.use(clerkMiddleware()); // populates what getAuth(req) reads in requireAuth (src/middleware/auth.ts)

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  app.use("/auth", authRouter);
  app.use(usersRouter);
  app.use(securityRouter);
  app.use("/clients", clientsRouter);
  app.use("/engagements", engagementsRouter);
  // Below routers declare their own full path (e.g. "/engagements/:id/assets"
  // or "/findings/:id") so they mount at root rather than under a fixed prefix.
  app.use(assetsRouter);
  app.use(testsRouter);
  app.use(findingsRouter);
  app.use(evidenceRouter);
  app.use(complianceRouter);
  app.use(reportsRouter);
  app.use(retestsRouter);
  app.use(trainingRouter);
  app.use(scanRouter);
  app.use(discoveryRouter);
  app.use(agentsRouter);
  app.use(internalRotationRouter);
  app.use(internalScheduledScansRouter);
  app.use(internalScheduledWatchRouter);
  app.use(internalBackupRouter);
  app.use(internalDigestRouter);
  app.use(internalSentryTestRouter);
  app.use(cspmRouter);
  app.use(sbomRouter);
  app.use(byokRouter);
  app.use("/audit-logs", auditRouter);

  app.use(async (err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    (req.log ?? logger).error({ err }, "Unhandled request error");
    // Awaited, not fire-and-forget: on Vercel the function's execution
    // context can freeze the instant the response finishes, which would
    // silently kill Sentry's in-flight delivery if this ran after
    // res.json() rather than before it — see captureException's own
    // comment in config/sentry.ts.
    await captureException(err);
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}

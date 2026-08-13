import * as Sentry from "@sentry/node";
import { env } from "./env";
import { logger } from "./logger";

// Optional, same graceful-degradation pattern as every other integration in
// this app: unset SENTRY_DSN means this is a no-op (errors still go to the
// pino logs, exactly as before) rather than something that needs to be
// configured before the server can start. Must run before anything else
// that might throw — imported first thing in server.ts.
export function initSentry(): void {
  if (!env.sentryDsn) {
    logger.warn("SENTRY_DSN is unset — errors will only be visible in this process's own logs, not reported anywhere centrally.");
    return;
  }
  Sentry.init({ dsn: env.sentryDsn, tracesSampleRate: 0.1 });
}

export function captureException(err: unknown): void {
  if (!env.sentryDsn) return;
  Sentry.captureException(err);
}

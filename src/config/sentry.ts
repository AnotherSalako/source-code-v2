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
  Sentry.init({
    dsn: env.sentryDsn,
    tracesSampleRate: 0.1,
    // This SDK's un-overridden defaults collect full HTTP request/response
    // bodies AND local stack-frame variable values on every captured error
    // — fine for most apps, a real contradiction of this one's whole design
    // for this one. Route bodies here routinely carry plaintext secrets
    // before they're ever encrypted (BYOK access/secret keys in PUT
    // .../kms-credential, finding descriptions, client contact info,
    // cloud credentials); local variables in the crypto module's stack
    // frames routinely hold decrypted plaintext and raw unwrapped DEK bytes
    // (src/crypto/envelope.ts's `plaintextKey`/`plaintext`) for the
    // duration of an encrypt/decrypt call. Sending either to a third-party
    // SaaS by default would leak exactly the class of data this app's
    // envelope encryption exists to keep from ever leaving app custody in
    // plaintext. Cookies (Clerk session cookies) and auto-populated user
    // info are disabled for the same reason — nothing here trades away
    // useful stack traces/error messages, only the categories of data that
    // could themselves be the sensitive thing.
    dataCollection: {
      httpBodies: [],
      stackFrameVariables: false,
      cookies: false,
      userInfo: false,
    },
  });
}

export function captureException(err: unknown): void {
  if (!env.sentryDsn) return;
  Sentry.captureException(err);
}

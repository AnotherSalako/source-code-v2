import rateLimit from "express-rate-limit";

// Keyed by req.ip (trust proxy is set to exactly one hop in app.ts, so this
// is the real client IP behind the single front-end proxy, not the proxy's
// own address) rather than by user — most requests here are unauthenticated
// at the point rate limiting runs (Clerk's middleware hasn't resolved a user
// yet), and IP-based throttling is what actually stops a script hammering
// the API regardless of whether it ever presents a valid token.

// General ceiling on the whole API — generous enough that a real dashboard
// session (which fires several GETs per page) never trips it, but still
// blocks a script hammering endpoints in a loop.
export const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/health",
});

// Applied per-route to anything that sends a real external email/notification
// or kicks off an expensive operation (a scan, a PDF report, an e-signature
// request) — these are worth throttling far tighter than ordinary reads,
// since abusing them means spamming a real inbox or burning real compute.
export const sideEffectLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

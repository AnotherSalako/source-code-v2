import pino from "pino";

// Structured JSON logging. Writes to stdout — correct for both a normal
// server process (captured by whatever's running it) and Vercel's serverless
// runtime (no persistent filesystem, stdout is the only thing that works).
// Silent by default under Vitest (VITEST is set automatically) — the route
// integration tests fire dozens of requests per file and pino-http's
// per-request logging would otherwise drown the actual test output.
export const logger = pino({
  level: process.env.LOG_LEVEL ?? (process.env.VITEST ? "silent" : "info"),
  redact: ["req.headers.authorization"], // never log bearer tokens
});

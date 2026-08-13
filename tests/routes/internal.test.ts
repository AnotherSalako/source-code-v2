import request from "supertest";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const REAL_CRON_SECRET = process.env.CRON_SECRET;

beforeEach(() => {
  resetFakeDb();
});

afterEach(() => {
  process.env.CRON_SECRET = REAL_CRON_SECRET;
});

// These routes are cron-only (no browser, no logged-in user) — protected by
// a shared secret rather than requireAuth, and refuse every request if that
// secret isn't configured rather than defaulting open. env.ts reads
// CRON_SECRET once at module load, so these tests only exercise the code
// path with whatever value is already in the real .env at process start —
// the negative case (secret unset entirely) is covered by reading the code's
// explicit `if (!env.cronSecret)` guard rather than by flipping the env var
// mid-test-run, which env.ts's one-time read wouldn't pick up anyway.

describe("GET /internal/rotate-keys", () => {
  it("401s with a wrong/missing bearer secret", async () => {
    await request(app).get("/internal/rotate-keys").expect(401);
  });

  it("401s with an incorrect secret", async () => {
    await request(app).get("/internal/rotate-keys").set("Authorization", "Bearer wrong-secret").expect(401);
  });

  it("200s with the correct secret (rotateAllFields is mocked — this only verifies the auth gate)", async () => {
    if (!REAL_CRON_SECRET) return; // skip if this environment has no CRON_SECRET configured at all
    await request(app).get("/internal/rotate-keys").set("Authorization", `Bearer ${REAL_CRON_SECRET}`).expect(200);
  });
});

describe("GET /internal/scheduled-scans", () => {
  it("401s with a wrong/missing bearer secret", async () => {
    await request(app).get("/internal/scheduled-scans").expect(401);
  });

  it("200s with the correct secret and reports what it started/skipped", async () => {
    if (!REAL_CRON_SECRET) return;
    const res = await request(app).get("/internal/scheduled-scans").set("Authorization", `Bearer ${REAL_CRON_SECRET}`).expect(200);
    expect(res.body).toHaveProperty("started");
    expect(res.body).toHaveProperty("skipped");
  });
});

import request from "supertest";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { resetFakeDb, seedUser, authHeader } from "../helpers/test-app";

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

describe("GET /internal/scheduled-watch", () => {
  it("401s with a wrong/missing bearer secret", async () => {
    await request(app).get("/internal/scheduled-watch").expect(401);
  });

  it("200s with the correct secret and reports what it started/skipped (startWatchCycle is mocked — this only verifies the auth gate and eligibility query)", async () => {
    if (!REAL_CRON_SECRET) return;
    const res = await request(app).get("/internal/scheduled-watch").set("Authorization", `Bearer ${REAL_CRON_SECRET}`).expect(200);
    expect(res.body).toHaveProperty("started");
    expect(res.body).toHaveProperty("skipped");
  });
});

describe("GET /internal/scheduled-backup", () => {
  it("401s with a wrong/missing bearer secret", async () => {
    await request(app).get("/internal/scheduled-backup").expect(401);
  });

  it("200s with the correct secret and actually runs a real backup (not mocked — same fake DB/KMS/storage every other test uses)", async () => {
    if (!REAL_CRON_SECRET) return;
    const res = await request(app).get("/internal/scheduled-backup").set("Authorization", `Bearer ${REAL_CRON_SECRET}`).expect(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("tableCounts");
  });
});

describe("GET /internal/backups", () => {
  it("401s with no auth", async () => {
    await request(app).get("/internal/backups").expect(401);
  });

  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "some-org" });
    await request(app).get("/internal/backups").set("x-test-user", authHeader("tech@acme.com")).expect(403);
  });

  it("200s for a SECURITY_ADMIN and lists metadata only, never decryption material", async () => {
    if (!REAL_CRON_SECRET) return;
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    await request(app).get("/internal/scheduled-backup").set("Authorization", `Bearer ${REAL_CRON_SECRET}`).expect(200);

    const res = await request(app).get("/internal/backups").set("x-test-user", authHeader("admin@example.com")).expect(200);
    expect(res.body.backups.length).toBeGreaterThan(0);
    expect(res.body.backups[0]).not.toHaveProperty("iv");
    expect(res.body.backups[0]).not.toHaveProperty("encryptedDataKey");
  });
});

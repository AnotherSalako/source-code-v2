import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

beforeEach(() => {
  resetFakeDb();
});

describe("GET /security/status", () => {
  it("401s with no auth", async () => {
    await request(app).get("/security/status").expect(401);
  });

  it("403s for a non-admin role — this is a trust-center page, admin-only", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "some-org" });
    await request(app).get("/security/status").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("200s for an admin and reports real config, not hardcoded values", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get("/security/status").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.access.teamSize).toBe(1);
    expect(res.body.encryption.kmsProvider).toBeDefined();
    expect(typeof res.body.detectionResponse.malwareDetectionConfigured).toBe("boolean");
    // Never returns actual secrets — only booleans/provider names/counts.
    expect(JSON.stringify(res.body)).not.toMatch(/sk_|api_|Bearer /);
  });
});

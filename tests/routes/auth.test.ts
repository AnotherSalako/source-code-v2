import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

beforeEach(() => {
  resetFakeDb();
});

describe("GET /auth/me", () => {
  it("401s with no auth header at all", async () => {
    await request(app).get("/auth/me").expect(401);
  });

  it("403s for a Clerk-authenticated caller with no matching User row (signed in but not provisioned in Jupiter)", async () => {
    await request(app).get("/auth/me").set("x-test-user", "stranger@example.com").expect(403);
  });

  it("200s and resolves the caller's own role/org — never someone else's", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "org-1" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).get("/auth/me").set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body.role).toBe("TECHNICAL_CLIENT");
    expect(res.body.orgId).toBe("org-1");
  });
});

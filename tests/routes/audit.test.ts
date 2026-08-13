import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

beforeEach(() => {
  resetFakeDb();
});

describe("GET /audit-logs", () => {
  it("401s with no auth", async () => {
    await request(app).get("/audit-logs").expect(401);
  });

  it("403s for a non-admin role — audit trail is internal-staff only", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "some-org" });
    await request(app).get("/audit-logs").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("200s for an admin, and every denied access attempt above shows up in the trail", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "some-org" });

    await request(app).get("/audit-logs").set("x-test-user", "tech@acme.com").expect(403); // generates a DENIED entry

    const res = await request(app).get("/audit-logs").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.some((l: any) => l.result === "DENIED")).toBe(true);
  });
});

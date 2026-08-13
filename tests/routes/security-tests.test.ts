import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEngagement, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const ASSET_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
});

describe("GET /engagements/:id/tests — cross-tenant IDOR protection", () => {
  it("404s for a different org's engagement", async () => {
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/engagements/eng-b/tests").set("x-test-user", "tech@acme.com").expect(404);
  });
});

describe("POST /engagements/:id/tests — hard-gated on signed authorization", () => {
  it("403s when the engagement has no signed authorization yet", async () => {
    seedEngagement({ id: "eng-a", clientId: CLIENT_A, authorizationSignedAt: null });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/engagements/eng-a/tests")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, type: "PENTEST" })
      .expect(403);
  });

  it("201s once the engagement is authorized", async () => {
    seedEngagement({ id: "eng-a", clientId: CLIENT_A, authorizationSignedAt: new Date() });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/engagements/eng-a/tests")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, type: "PENTEST" })
      .expect(201);
    expect(res.body.status).toBe("PLANNED");
  });

  it("403s for a non-admin role even when authorized", async () => {
    seedEngagement({ id: "eng-a", clientId: CLIENT_A, authorizationSignedAt: new Date() });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/tests")
      .set("x-test-user", "tech@acme.com")
      .send({ assetId: ASSET_ID, type: "PENTEST" })
      .expect(403);
  });
});

import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEngagement, seedAsset, seedTest, seedFinding, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
  seedEngagement({ id: "eng-a", clientId: CLIENT_A });
  seedAsset({ id: "asset-a", engagementId: "eng-a", type: "WEB", name: "Site" });
  seedTest({ id: "test-a", engagementId: "eng-a", assetId: "asset-a", type: "MANUAL", testerId: "admin" });
  seedFinding({ id: "finding-a", testId: "test-a", assetId: "asset-a", title: "Finding", severity: "HIGH", status: "REMEDIATING" });
});

describe("POST /findings/:id/retest", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post("/findings/finding-a/retest").set("x-test-user", "tech@acme.com").send({ result: "FIXED" }).expect(403);
  });

  it("201s and moves the finding's status to RETESTED_PASS on a FIXED result (both writes happen via $transaction)", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/findings/finding-a/retest").set("x-test-user", "admin@example.com").send({ result: "FIXED" }).expect(201);

    const list = await request(app).get("/engagements/eng-a/findings").set("x-test-user", "admin@example.com").expect(200);
    expect(list.body.find((f: any) => f.id === "finding-a").status).toBe("RETESTED_PASS");
  });

  it("moves the finding's status to RETESTED_FAIL on a NOT_FIXED result", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/findings/finding-a/retest").set("x-test-user", "admin@example.com").send({ result: "NOT_FIXED" }).expect(201);

    const list = await request(app).get("/engagements/eng-a/findings").set("x-test-user", "admin@example.com").expect(200);
    expect(list.body.find((f: any) => f.id === "finding-a").status).toBe("RETESTED_FAIL");
  });
});

describe("GET /findings/:id/retest-history — cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests retest history for a DIFFERENT org's finding", async () => {
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    seedAsset({ id: "asset-b", engagementId: "eng-b", type: "WEB", name: "Other site" });
    seedTest({ id: "test-b", engagementId: "eng-b", assetId: "asset-b", type: "MANUAL", testerId: "admin" });
    seedFinding({ id: "finding-b", testId: "test-b", assetId: "asset-b", title: "Other finding", severity: "HIGH" });

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/findings/finding-b/retest-history").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("notes are withheld from the list view even for an authorized caller", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/findings/finding-a/retest")
      .set("x-test-user", "admin@example.com")
      .send({ result: "PARTIALLY_FIXED", notes: "half the injection points are patched" })
      .expect(201);

    const res = await request(app).get("/findings/finding-a/retest-history").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].notesEnc).toBeUndefined();
  });
});

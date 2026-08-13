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
  seedFinding({ id: "finding-a", testId: "test-a", assetId: "asset-a", title: "Finding", severity: "HIGH" });
});

describe("POST /findings/:id/evidence (multipart upload)", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/findings/finding-a/evidence")
      .set("x-test-user", "tech@acme.com")
      .attach("file", Buffer.from("screenshot bytes"), "screenshot.png")
      .expect(403);
  });

  it("201s and stores the file for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/findings/finding-a/evidence")
      .set("x-test-user", "admin@example.com")
      .attach("file", Buffer.from("screenshot bytes"), "screenshot.png")
      .expect(201);
    expect(res.body.filename).toBe("screenshot.png");
  });
});

describe("GET /findings/:id/evidence/:evidenceId — cross-tenant IDOR protection + role gating", () => {
  it("404s when a client-role user requests evidence for a finding in a DIFFERENT org", async () => {
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    seedAsset({ id: "asset-b", engagementId: "eng-b", type: "WEB", name: "Other site" });
    seedTest({ id: "test-b", engagementId: "eng-b", assetId: "asset-b", type: "MANUAL", testerId: "admin" });
    seedFinding({ id: "finding-b", testId: "test-b", assetId: "asset-b", title: "Other finding", severity: "HIGH" });

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const uploaded = await request(app)
      .post("/findings/finding-b/evidence")
      .set("x-test-user", "admin@example.com")
      .attach("file", Buffer.from("secret bytes"), "secret.png")
      .expect(201);

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .get(`/findings/finding-b/evidence/${uploaded.body.id}`)
      .set("x-test-user", "tech@acme.com")
      .expect(404);
  });

  it("EXEC_CLIENT is blocked from downloading raw evidence files (403), even for their own org", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const uploaded = await request(app)
      .post("/findings/finding-a/evidence")
      .set("x-test-user", "admin@example.com")
      .attach("file", Buffer.from("screenshot bytes"), "screenshot.png")
      .expect(201);

    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: CLIENT_A });
    await request(app)
      .get(`/findings/finding-a/evidence/${uploaded.body.id}`)
      .set("x-test-user", "exec@acme.com")
      .expect(403);
  });

  it("TECHNICAL_CLIENT in the same org can download and gets the exact original bytes back", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const uploaded = await request(app)
      .post("/findings/finding-a/evidence")
      .set("x-test-user", "admin@example.com")
      .attach("file", Buffer.from("exact original bytes"), "screenshot.png")
      .expect(201);

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    const res = await request(app)
      .get(`/findings/finding-a/evidence/${uploaded.body.id}`)
      .set("x-test-user", "tech@acme.com")
      .expect(200);
    expect(res.body.toString()).toBe("exact original bytes");
  });

  it("EXEC_CLIENT sees an empty evidence list (not just blocked from individual downloads)", async () => {
    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: CLIENT_A });
    const res = await request(app).get("/findings/finding-a/evidence").set("x-test-user", "exec@acme.com").expect(200);
    expect(res.body).toEqual([]);
  });
});

import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEngagement, seedComplianceCheck, seedAsset, seedTest, seedFinding, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
  seedEngagement({ id: "eng-a", clientId: CLIENT_A });
  seedEngagement({ id: "eng-b", clientId: CLIENT_B });
});

describe("POST /engagements/:id/compliance-checks", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/compliance-checks")
      .set("x-test-user", "tech@acme.com")
      .send({ framework: "ISO27001", controlId: "A.5.1", controlName: "Policies", status: "PENDING" })
      .expect(403);
  });

  it("201s for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/engagements/eng-a/compliance-checks")
      .set("x-test-user", "admin@example.com")
      .send({ framework: "ISO27001", controlId: "A.5.1", controlName: "Policies for information security", status: "PENDING" })
      .expect(201);
    expect(res.body.controlId).toBe("A.5.1");
  });
});

describe("POST /engagements/:id/compliance-checks/seed", () => {
  it("seeds the standard control library and is idempotent on a second call", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const first = await request(app)
      .post("/engagements/eng-a/compliance-checks/seed")
      .set("x-test-user", "admin@example.com")
      .send({ framework: "ISO27001" })
      .expect(201);
    expect(first.body.created).toBeGreaterThan(0);

    const second = await request(app)
      .post("/engagements/eng-a/compliance-checks/seed")
      .set("x-test-user", "admin@example.com")
      .send({ framework: "ISO27001" })
      .expect(201);
    expect(second.body.created).toBe(0);
    expect(second.body.alreadyPresent).toBe(first.body.created);
  });
});

describe("PATCH /compliance-checks/:id", () => {
  it("403s for a non-admin role (this route is admin-only — requireRole gates it before assertOwnOrg is ever reached)", async () => {
    seedComplianceCheck({ id: "check-a", engagementId: "eng-a", framework: "ISO27001", controlId: "A.5.1", controlName: "Policies" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .patch("/compliance-checks/check-a")
      .set("x-test-user", "tech@acme.com")
      .send({ status: "PASS" })
      .expect(403);
  });

  it("200s and updates status for an admin", async () => {
    seedComplianceCheck({ id: "check-a", engagementId: "eng-a", framework: "ISO27001", controlId: "A.5.1", controlName: "Policies" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .patch("/compliance-checks/check-a")
      .set("x-test-user", "admin@example.com")
      .send({ status: "PASS" })
      .expect(200);
    expect(res.body.status).toBe("PASS");
  });
});

describe("GET /engagements/:id/compliance-summary", () => {
  it("404s for a different org's engagement", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/engagements/eng-b/compliance-summary").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("summarizes counts by framework and status", async () => {
    seedComplianceCheck({ id: "c1", engagementId: "eng-a", framework: "ISO27001", controlId: "A.5.1", controlName: "x", status: "PASS" });
    seedComplianceCheck({ id: "c2", engagementId: "eng-a", framework: "ISO27001", controlId: "A.5.2", controlName: "y", status: "FAIL" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).get("/engagements/eng-a/compliance-summary").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.totalControls).toBe(2);
    expect(res.body.byFramework.ISO27001.PASS).toBe(1);
    expect(res.body.byFramework.ISO27001.FAIL).toBe(1);
  });
});

describe("GET /engagements/:id/compliance-mapping", () => {
  const ASSET_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";

  it("404s for a different org's engagement", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/engagements/eng-b/compliance-mapping").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("maps an actionable finding's title to relevant controls", async () => {
    seedAsset({ id: ASSET_ID, engagementId: "eng-a", type: "WEB", name: "Site" });
    seedTest({ id: "test-a", engagementId: "eng-a", assetId: ASSET_ID, type: "VULN_SCAN", testerId: "user_admin" });
    seedFinding({ id: "f1", testId: "test-a", assetId: ASSET_ID, title: "SQL injection in login form", severity: "CRITICAL", status: "OPEN" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).get("/engagements/eng-a/compliance-mapping").set("x-test-user", "admin@example.com").expect(200);

    expect(res.body.findings).toHaveLength(1);
    expect(res.body.findings[0].findingId).toBe("f1");
    expect(res.body.findings[0].mappedControls).toContainEqual({ framework: "ISO27001", controlId: "A.8.28", controlName: "Secure coding" });
  });

  it("includes a finding with an empty mappedControls array rather than omitting it", async () => {
    seedAsset({ id: ASSET_ID, engagementId: "eng-a", type: "WEB", name: "Site" });
    seedTest({ id: "test-a", engagementId: "eng-a", assetId: ASSET_ID, type: "VULN_SCAN", testerId: "user_admin" });
    seedFinding({ id: "f1", testId: "test-a", assetId: ASSET_ID, title: "Server responds slowly under load", severity: "LOW", status: "OPEN" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).get("/engagements/eng-a/compliance-mapping").set("x-test-user", "admin@example.com").expect(200);

    expect(res.body.findings).toHaveLength(1);
    expect(res.body.findings[0].mappedControls).toEqual([]);
  });

  it("excludes RETESTED_PASS and ACCEPTED_RISK findings — nothing still-actionable to map", async () => {
    seedAsset({ id: ASSET_ID, engagementId: "eng-a", type: "WEB", name: "Site" });
    seedTest({ id: "test-a", engagementId: "eng-a", assetId: ASSET_ID, type: "VULN_SCAN", testerId: "user_admin" });
    seedFinding({ id: "fixed", testId: "test-a", assetId: ASSET_ID, title: "SQL injection", severity: "CRITICAL", status: "RETESTED_PASS" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).get("/engagements/eng-a/compliance-mapping").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.findings).toEqual([]);
  });
});

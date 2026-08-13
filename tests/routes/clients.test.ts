import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import {
  seedClient,
  seedUser,
  seedEngagement,
  seedAsset,
  seedTest,
  seedFinding,
  seedEvidence,
  seedReport,
  seedRetest,
  seedComplianceCheck,
  seedTrainingSession,
  seedScanJob,
  resetFakeDb,
} from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

beforeEach(() => {
  resetFakeDb();
});

describe("GET /clients", () => {
  it("401s with no auth header at all", async () => {
    await request(app).get("/clients").expect(401);
  });

  it("403s for a Clerk-authenticated caller with no matching User row (not provisioned)", async () => {
    await request(app).get("/clients").set("x-test-user", "ghost@example.com").expect(403);
  });

  it("SECURITY_ADMIN sees every client", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-a", name: "Acme" });
    seedClient({ id: "client-b", name: "Beta Corp" });

    const res = await request(app).get("/clients").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body).toHaveLength(2);
  });

  it("a client-role user sees only their own org, never a directory of every client", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });
    seedClient({ id: "client-b", name: "Beta Corp — not this caller's org" });

    const res = await request(app).get("/clients").set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].id).toBe("client-a");
  });
});

describe("GET /clients/:id — cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a DIFFERENT org's client record by ID", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });
    seedClient({ id: "client-b", name: "Beta Corp" });

    // The exact attack this session live-tested against a real deployment —
    // a client-scoped account trying to fetch another client's record by ID.
    await request(app).get("/clients/client-b").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("200s when a client-role user requests their OWN org's client record", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });

    const res = await request(app).get("/clients/client-a").set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body.id).toBe("client-a");
  });

  it("SECURITY_ADMIN can fetch any client's record regardless of org", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-b", name: "Beta Corp" });

    await request(app).get("/clients/client-b").set("x-test-user", "admin@example.com").expect(200);
  });
});

describe("POST /clients", () => {
  it("403s for a non-admin role (client-side users can't create client records)", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    await request(app).post("/clients").set("x-test-user", "tech@acme.com").send({ name: "New Co" }).expect(403);
  });

  it("400s when name is missing", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/clients").set("x-test-user", "admin@example.com").send({}).expect(400);
  });

  it("400s when name exceeds the 200-char cap (regression test for the input-validation hardening this session)", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/clients")
      .set("x-test-user", "admin@example.com")
      .send({ name: "x".repeat(201) })
      .expect(400);
  });

  it("201s and creates the client for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/clients")
      .set("x-test-user", "admin@example.com")
      .send({ name: "  New Co  " }) // leading/trailing whitespace — should come back trimmed
      .expect(201);
    expect(res.body.name).toBe("New Co");
  });
});

// Seeds a full dependency graph under one client — engagement, asset, test,
// finding, evidence, retest, compliance check, report, training session,
// scan job — so the erasure flow has every model type to actually walk.
function seedFullGraph(clientId: string, suffix: string) {
  const engagementId = `engagement-${suffix}`;
  const assetId = `asset-${suffix}`;
  const testId = `test-${suffix}`;
  const findingId = `finding-${suffix}`;
  seedEngagement({ id: engagementId, clientId, authorizationDocRef: `authdocs/${suffix}` });
  seedAsset({ id: assetId, engagementId, type: "WEB", name: `Asset ${suffix}` });
  seedTest({ id: testId, engagementId, assetId, type: "PENTEST", testerId: "tester-1" });
  seedFinding({ id: findingId, testId, assetId, title: `Finding ${suffix}`, severity: "HIGH" });
  seedEvidence({ id: `evidence-${suffix}`, findingId, originalFilename: "shot.png", storageKey: `evidence/${suffix}` });
  seedRetest({ id: `retest-${suffix}`, findingId, retestedBy: "tester-1", result: "FIXED" });
  seedComplianceCheck({ id: `compliance-${suffix}`, engagementId, framework: "ISO27001", controlId: "A.5.1", controlName: "Policies" });
  seedReport({ id: `report-${suffix}`, engagementId, type: "TECHNICAL", storageKey: `reports/${suffix}` });
  seedTrainingSession({ id: `training-${suffix}`, engagementId, topic: "PHISHING" });
  seedScanJob({ id: `scanjob-${suffix}`, engagementId, assetId, testId, triggeredById: "tester-1" });
  return { engagementId, assetId, testId, findingId };
}

describe("DELETE /clients/:id — self-service data erasure", () => {
  it("401s with no auth header", async () => {
    seedClient({ id: "client-a", name: "Acme" });
    await request(app).delete("/clients/client-a").send({ confirmName: "Acme" }).expect(401);
  });

  it("403s a TECHNICAL_CLIENT of the client's own org — not an account-level decision they can make", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });

    await request(app)
      .delete("/clients/client-a")
      .set("x-test-user", "tech@acme.com")
      .send({ confirmName: "Acme" })
      .expect(403);

    // Nothing erased.
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).get("/clients/client-a").set("x-test-user", "admin@example.com").expect(200);
  });

  it("404s when an EXEC_CLIENT tries to erase a DIFFERENT org's data (cross-tenant IDOR)", async () => {
    seedUser({ email: "exec@beta.com", name: "Exec", role: "EXEC_CLIENT", orgId: "client-b" });
    seedClient({ id: "client-a", name: "Acme" });
    seedClient({ id: "client-b", name: "Beta Corp" });

    await request(app)
      .delete("/clients/client-a")
      .set("x-test-user", "exec@beta.com")
      .send({ confirmName: "Acme" })
      .expect(404);
  });

  it("400s when confirmName doesn't match the client's real name — refuses to erase anything", async () => {
    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });
    seedFullGraph("client-a", "a1");

    await request(app)
      .delete("/clients/client-a")
      .set("x-test-user", "exec@acme.com")
      .send({ confirmName: "wrong name" })
      .expect(400);

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).get("/clients/client-a").set("x-test-user", "admin@example.com").expect(200);
  });

  it("EXEC_CLIENT can self-service-erase their OWN org's entire data graph, leaving other clients and AuditLog untouched", async () => {
    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: "client-a" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-a", name: "Acme" });
    seedClient({ id: "client-b", name: "Beta Corp — must survive" });
    seedFullGraph("client-a", "a1");
    seedFullGraph("client-b", "b1");
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });

    // Generate a pre-existing audit trail entry before erasure, to prove
    // AuditLog rows are preserved (append-only), not wiped along with the client.
    await request(app).get("/clients/client-a").set("x-test-user", "exec@acme.com").expect(200);
    const before = await request(app).get("/audit-logs").set("x-test-user", "admin@example.com").expect(200);
    const beforeCount = before.body.length;

    const res = await request(app)
      .delete("/clients/client-a")
      .set("x-test-user", "exec@acme.com")
      .send({ confirmName: "Acme" })
      .expect(200);

    expect(res.body.deletedCounts).toMatchObject({
      retest: 1,
      evidence: 1,
      scanJob: 1,
      finding: 1,
      complianceCheck: 1,
      report: 1,
      trainingSession: 1,
      test: 1,
      asset: 1,
      engagement: 1,
      user: 2, // exec@acme.com (the caller) + tech@acme.com, both orgId client-a
      client: 1,
    });
    expect(res.body.storageKeysDeleted).toBe(3); // evidence file + report file + authorization doc

    // Client-a genuinely gone.
    await request(app).get("/clients/client-a").set("x-test-user", "admin@example.com").expect(404);

    // Client-b's entire graph is untouched.
    await request(app).get("/clients/client-b").set("x-test-user", "admin@example.com").expect(200);

    // AuditLog preserved: the pre-erasure VIEW entry is still there, plus a
    // new DELETE entry documenting the erasure itself — nothing was purged.
    const after = await request(app).get("/audit-logs").set("x-test-user", "admin@example.com").expect(200);
    expect(after.body.length).toBeGreaterThan(beforeCount);
    expect(after.body.some((l: any) => l.action === "DELETE" && l.resourceType === "client.erasure" && l.resourceId === "client-a")).toBe(true);
  });

  it("SECURITY_ADMIN can erase a client's data on their behalf (support-assisted path)", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-a", name: "Acme" });
    seedFullGraph("client-a", "a1");

    await request(app)
      .delete("/clients/client-a")
      .set("x-test-user", "admin@example.com")
      .send({ confirmName: "Acme" })
      .expect(200);

    await request(app).get("/clients/client-a").set("x-test-user", "admin@example.com").expect(404);
  });
});

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
  seedUsageEvent,
  resetFakeDb,
  getRawFinding,
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

describe("PATCH /clients/:id/kms-key — per-tenant encryption keys", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });
    await request(app)
      .patch("/clients/client-a/kms-key")
      .set("x-test-user", "tech@acme.com")
      .send({ kmsKeyId: "arn:aws:kms:...:key/tenant-a" })
      .expect(403);
  });

  it("404s for a nonexistent client", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .patch("/clients/does-not-exist/kms-key")
      .set("x-test-user", "admin@example.com")
      .send({ kmsKeyId: "tenant-key" })
      .expect(404);
  });

  it("400s on an empty kmsKeyId", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-a", name: "Acme" });
    await request(app)
      .patch("/clients/client-a/kms-key")
      .set("x-test-user", "admin@example.com")
      .send({ kmsKeyId: "" })
      .expect(400);
  });

  it("200s and assigns the key for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-a", name: "Acme" });
    const res = await request(app)
      .patch("/clients/client-a/kms-key")
      .set("x-test-user", "admin@example.com")
      .send({ kmsKeyId: "tenant-a-key" })
      .expect(200);
    expect(res.body.kmsKeyId).toBe("tenant-a-key");
  });

  it(
    "two clients with different assigned keys have their findings genuinely encrypted under different keys, " +
      "each still decrypting correctly end to end through the real API — not just labeled differently",
    async () => {
      const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
      const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
      seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
      seedClient({ id: CLIENT_A, name: "Acme" });
      seedClient({ id: CLIENT_B, name: "Beta Corp" });

      await request(app)
        .patch(`/clients/${CLIENT_A}/kms-key`)
        .set("x-test-user", "admin@example.com")
        .send({ kmsKeyId: "tenant-a-key" })
        .expect(200);
      await request(app)
        .patch(`/clients/${CLIENT_B}/kms-key`)
        .set("x-test-user", "admin@example.com")
        .send({ kmsKeyId: "tenant-b-key" })
        .expect(200);

      const engA = await request(app)
        .post("/engagements")
        .set("x-test-user", "admin@example.com")
        .send({ clientId: CLIENT_A })
        .expect(201);
      const engB = await request(app)
        .post("/engagements")
        .set("x-test-user", "admin@example.com")
        .send({ clientId: CLIENT_B })
        .expect(201);
      await request(app)
        .post(`/engagements/${engA.body.id}/authorize`)
        .set("x-test-user", "admin@example.com")
        .send({ authorizedBy: "Acme CISO", authorizationDocRef: "docs/a" })
        .expect(200);
      await request(app)
        .post(`/engagements/${engB.body.id}/authorize`)
        .set("x-test-user", "admin@example.com")
        .send({ authorizedBy: "Beta CISO", authorizationDocRef: "docs/b" })
        .expect(200);

      const assetA = await request(app)
        .post(`/engagements/${engA.body.id}/assets`)
        .set("x-test-user", "admin@example.com")
        .send({ type: "WEB", name: "Site A", identifier: "a.example.com" })
        .expect(201);
      const assetB = await request(app)
        .post(`/engagements/${engB.body.id}/assets`)
        .set("x-test-user", "admin@example.com")
        .send({ type: "WEB", name: "Site B", identifier: "b.example.com" })
        .expect(201);

      const testA = await request(app)
        .post(`/engagements/${engA.body.id}/tests`)
        .set("x-test-user", "admin@example.com")
        .send({ assetId: assetA.body.id, type: "PENTEST" })
        .expect(201);
      const testB = await request(app)
        .post(`/engagements/${engB.body.id}/tests`)
        .set("x-test-user", "admin@example.com")
        .send({ assetId: assetB.body.id, type: "PENTEST" })
        .expect(201);

      const findingA = await request(app)
        .post(`/engagements/${engA.body.id}/tests/${testA.body.id}/findings`)
        .set("x-test-user", "admin@example.com")
        .send({ assetId: assetA.body.id, title: "Client A's finding", description: "A-specific detail", severity: "HIGH" })
        .expect(201);
      const findingB = await request(app)
        .post(`/engagements/${engB.body.id}/tests/${testB.body.id}/findings`)
        .set("x-test-user", "admin@example.com")
        .send({ assetId: assetB.body.id, title: "Client B's finding", description: "B-specific detail", severity: "HIGH" })
        .expect(201);

      // The actual security property: each finding's descriptionEnc is
      // wrapped under its OWN client's assigned key, not a shared one.
      const rawA = getRawFinding(findingA.body.id);
      const rawB = getRawFinding(findingB.body.id);
      expect((rawA?.descriptionEnc as any).kmsKeyId).toBe("tenant-a-key");
      expect((rawB?.descriptionEnc as any).kmsKeyId).toBe("tenant-b-key");
      expect((rawA?.descriptionEnc as any).kmsKeyId).not.toBe((rawB?.descriptionEnc as any).kmsKeyId);

      // And each still decrypts correctly through the ordinary read path —
      // per-tenant keys are additive, never a decrypt-side special case.
      seedUser({ email: "techA@acme.com", name: "TechA", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
      seedUser({ email: "techB@beta.com", name: "TechB", role: "TECHNICAL_CLIENT", orgId: CLIENT_B });
      const getA = await request(app).get(`/findings/${findingA.body.id}`).set("x-test-user", "techA@acme.com").expect(200);
      const getB = await request(app).get(`/findings/${findingB.body.id}`).set("x-test-user", "techB@beta.com").expect(200);
      expect(getA.body.description).toBe("A-specific detail");
      expect(getB.body.description).toBe("B-specific detail");
    }
  );
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

describe("GET /clients/:id/usage", () => {
  it("401s with no auth", async () => {
    seedClient({ id: "client-a", name: "Acme" });
    await request(app).get("/clients/client-a/usage").expect(401);
  });

  it("404s when a client-role user requests a DIFFERENT org's usage — same IDOR protection as the client record itself", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });
    seedClient({ id: "client-b", name: "Beta Corp" });

    await request(app).get("/clients/client-b/usage").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("reports both all-time and recent-window counts for the caller's own org", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "client-a" });
    seedClient({ id: "client-a", name: "Acme" });
    seedUsageEvent("client-a", "SCAN");
    seedUsageEvent("client-a", "SCAN");
    seedUsageEvent("client-a", "DISCOVERY");
    seedUsageEvent("client-a", "AGENT_CHECK_IN", { createdAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) }); // outside the default 30-day window

    const res = await request(app).get("/clients/client-a/usage").set("x-test-user", "tech@acme.com").expect(200);

    expect(res.body.allTime).toEqual({ scansRun: 2, discoveryRuns: 1, agentCheckIns: 1, aiCalls: 0 });
    expect(res.body.recent.scansRun).toBe(2);
    expect(res.body.recent.agentCheckIns).toBe(0); // the 90-day-old check-in falls outside the 30-day recent window
    expect(res.body.recent.sinceDays).toBe(30);
  });

  it("accepts a custom ?days= window, clamped to a sane range", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedClient({ id: "client-a", name: "Acme" });

    const res = await request(app).get("/clients/client-a/usage?days=7").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.recent.sinceDays).toBe(7);
  });
});

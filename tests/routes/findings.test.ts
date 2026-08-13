import request from "supertest";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { seedUser, seedClient, seedEngagement, seedAsset, seedTest, seedFinding, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();
const { aiTriage, nlQuery } = await import("../../src/ai");

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const ASSET_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
  seedEngagement({ id: "eng-a", clientId: CLIENT_A });
  seedEngagement({ id: "eng-b", clientId: CLIENT_B });
  seedAsset({ id: ASSET_ID, engagementId: "eng-a", type: "WEB", name: "Site" });
  seedTest({ id: "test-a", engagementId: "eng-a", assetId: ASSET_ID, type: "MANUAL", testerId: "user_admin" });
});

describe("POST /engagements/:id/tests/:testId/findings", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "tech@acme.com")
      .send({ assetId: ASSET_ID, title: "XSS", description: "reflected xss", severity: "HIGH" })
      .expect(403);
  });

  it("400s when the title exceeds the 300-char cap", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "x".repeat(301), description: "d", severity: "LOW" })
      .expect(400);
  });

  it("201s for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "Reflected XSS on /search", description: "details here", severity: "HIGH" })
      .expect(201);
    expect(res.body.severity).toBe("HIGH");
  });
});

describe("GET /findings/:id — role-gated detail + cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a finding belonging to a DIFFERENT org", async () => {
    seedEngagement({ id: "eng-b2", clientId: CLIENT_B });
    seedAsset({ id: "asset-b", engagementId: "eng-b2", type: "WEB", name: "Other site" });
    seedTest({ id: "test-b", engagementId: "eng-b2", assetId: "asset-b", type: "MANUAL", testerId: "user_admin" });
    seedFinding({ id: "finding-b", testId: "test-b", assetId: "asset-b", title: "Someone else's finding", severity: "HIGH" });

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/findings/finding-b").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("EXEC_CLIENT gets only the business-risk view — no description/reproduction steps", async () => {
    seedFinding({ id: "finding-a", testId: "test-a", assetId: ASSET_ID, title: "SQLi", severity: "CRITICAL" });
    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: CLIENT_A });

    const res = await request(app).get("/findings/finding-a").set("x-test-user", "exec@acme.com").expect(200);
    expect(res.body.title).toBe("SQLi");
    expect(res.body.description).toBeUndefined();
  });

  it("TECHNICAL_CLIENT gets the full decrypted finding, including description", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "SQLi on /login", description: "full technical detail here", severity: "CRITICAL" })
      .expect(201);

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    const res = await request(app).get(`/findings/${created.body.id}`).set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body.description).toBe("full technical detail here");
  });
});

describe("POST /findings/:id/response-actions/contain", () => {
  it("resolves the target from the finding's own asset, not an arbitrary request body value", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    // Created through the real endpoint (not seedAsset) so identifierEnc is
    // genuinely encrypted — the contain route decrypts it for real.
    const realAsset = await request(app)
      .post("/engagements/eng-a/assets")
      .set("x-test-user", "admin@example.com")
      .send({ type: "SERVER", name: "Compromised host", identifier: "10.0.0.5" })
      .expect(201);
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: realAsset.body.id, title: "Compromised host", description: "d", severity: "CRITICAL" })
      .expect(201);

    // Even if a caller tries to smuggle a different target in the body, the
    // route ignores it — it only ever resolves the finding's own asset.
    const res = await request(app)
      .post(`/findings/${created.body.id}/response-actions/contain`)
      .set("x-test-user", "admin@example.com")
      .send({ target: "some-other-host.evil.com" })
      .expect(200);
    expect(res.body.success).toBe(true);
  });
});

describe("AI-assisted triage — advisory-only, never auto-applied", () => {
  it("POST /findings/:id/triage returns drafted:false when no provider is configured (noop default)", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "XSS", description: "reflected xss on /search", severity: "HIGH" })
      .expect(201);

    const res = await request(app).post(`/findings/${created.body.id}/triage`).set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.drafted).toBe(false);
  });

  it("403s the triage endpoint for a non-admin role", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "X", description: "d", severity: "LOW" })
      .expect(201);

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post(`/findings/${created.body.id}/triage`).set("x-test-user", "tech@acme.com").expect(403);
  });

  it("stores a draft when the provider returns one, visible on GET, without touching the real remediationGuidance", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "Missing CSP header", description: "no content-security-policy header set", severity: "MEDIUM" })
      .expect(201);

    vi.mocked(aiTriage.draftTriage).mockResolvedValueOnce({
      remediationGuidance: "Add a Content-Security-Policy header restricting script-src to self.",
      falsePositiveLikelihood: "LOW",
      rationale: "The response genuinely lacks the header across all tested paths.",
    });

    const triageRes = await request(app).post(`/findings/${created.body.id}/triage`).set("x-test-user", "admin@example.com").expect(200);
    expect(triageRes.body.drafted).toBe(true);
    expect(triageRes.body.falsePositiveLikelihood).toBe("LOW");

    const getRes = await request(app).get(`/findings/${created.body.id}`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body.aiRemediationDraft).toContain("Content-Security-Policy");
    expect(getRes.body.aiFalsePositiveLikelihood).toBe("LOW");
    expect(getRes.body.remediationGuidance).toBeUndefined();
  });

  it("PATCH acceptAiRemediationDraft 400s when no draft exists yet", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "No draft yet", description: "d", severity: "LOW" })
      .expect(201);

    await request(app)
      .patch(`/findings/${created.body.id}`)
      .set("x-test-user", "admin@example.com")
      .send({ acceptAiRemediationDraft: true })
      .expect(400);
  });

  it("PATCH acceptAiRemediationDraft promotes the draft into the real remediationGuidance", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const created = await request(app)
      .post("/engagements/eng-a/tests/test-a/findings")
      .set("x-test-user", "admin@example.com")
      .send({ assetId: ASSET_ID, title: "Weak TLS config", description: "TLS 1.0 still enabled", severity: "MEDIUM" })
      .expect(201);

    vi.mocked(aiTriage.draftTriage).mockResolvedValueOnce({
      remediationGuidance: "Disable TLS 1.0/1.1 in the server config and require TLS 1.2+.",
      falsePositiveLikelihood: "LOW",
      rationale: "Confirmed via handshake test.",
    });
    await request(app).post(`/findings/${created.body.id}/triage`).set("x-test-user", "admin@example.com").expect(200);

    await request(app)
      .patch(`/findings/${created.body.id}`)
      .set("x-test-user", "admin@example.com")
      .send({ acceptAiRemediationDraft: true })
      .expect(200);

    const getRes = await request(app).get(`/findings/${created.body.id}`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body.remediationGuidance).toBe("Disable TLS 1.0/1.1 in the server config and require TLS 1.2+.");
  });
});

describe("GET /engagements/:id/findings/clusters — structural dedup + exploitability ranking", () => {
  it("404s when a client-role user requests a DIFFERENT org's engagement", async () => {
    seedUser({ email: "tech@beta.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_B });
    await request(app).get("/engagements/eng-a/findings/clusters").set("x-test-user", "tech@beta.com").expect(404);
  });

  it("groups near-duplicate titles across different assets into one cluster, keeps a dissimilar title separate", async () => {
    const assetB = "dddddddd-dddd-dddd-dddd-dddddddddddd";
    seedAsset({ id: assetB, engagementId: "eng-a", type: "WEB", name: "Second site" });
    seedTest({ id: "test-b", engagementId: "eng-a", assetId: assetB, type: "MANUAL", testerId: "user_admin" });

    seedFinding({ id: "f1", testId: "test-a", assetId: ASSET_ID, title: "Missing CSP header on /login", severity: "MEDIUM", status: "OPEN" });
    seedFinding({ id: "f2", testId: "test-b", assetId: assetB, title: "Missing CSP header on /admin/users", severity: "MEDIUM", status: "OPEN" });
    seedFinding({ id: "f3", testId: "test-a", assetId: ASSET_ID, title: "Outdated jQuery version in use", severity: "LOW", status: "OPEN" });

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get("/engagements/eng-a/findings/clusters").set("x-test-user", "admin@example.com").expect(200);

    expect(res.body.findings).toHaveLength(3);
    const cspCluster = res.body.clusters.find((c: any) => c.findingIds.includes("f1"));
    expect(cspCluster.findingIds.sort()).toEqual(["f1", "f2"]);
    expect(cspCluster.assetCount).toBe(2);
    expect(cspCluster.memberCount).toBe(2);

    const jqueryCluster = res.body.clusters.find((c: any) => c.findingIds.includes("f3"));
    expect(jqueryCluster.findingIds).toEqual(["f3"]);
    expect(res.body.clusters).toHaveLength(2);
  });

  it("ranks a CRITICAL open finding on an internet-facing asset above a MEDIUM finding on a non-internet-facing asset", async () => {
    const networkAsset = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
    seedAsset({ id: networkAsset, engagementId: "eng-a", type: "NETWORK", name: "Internal LAN segment" });
    seedTest({ id: "test-net", engagementId: "eng-a", assetId: networkAsset, type: "MANUAL", testerId: "user_admin" });

    seedFinding({ id: "critical-web", testId: "test-a", assetId: ASSET_ID, title: "Remote code execution via deserialization", severity: "CRITICAL", status: "OPEN" });
    seedFinding({ id: "medium-internal", testId: "test-net", assetId: networkAsset, title: "SNMP community string default", severity: "MEDIUM", status: "OPEN" });

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get("/engagements/eng-a/findings/clusters").set("x-test-user", "admin@example.com").expect(200);

    expect(res.body.findings[0].id).toBe("critical-web");
    expect(res.body.findings[0].exploitability.internetFacing).toBe(true);
    expect(res.body.findings[0].exploitability.score).toBeGreaterThan(res.body.findings[1].exploitability.score);
  });

  it("excludes RETESTED_PASS and ACCEPTED_RISK findings — nothing still-actionable to rank", async () => {
    seedFinding({ id: "fixed", testId: "test-a", assetId: ASSET_ID, title: "Fixed already", severity: "HIGH", status: "RETESTED_PASS" });
    seedFinding({ id: "accepted", testId: "test-a", assetId: ASSET_ID, title: "Accepted risk", severity: "HIGH", status: "ACCEPTED_RISK" });
    seedFinding({ id: "still-open", testId: "test-a", assetId: ASSET_ID, title: "Still open", severity: "HIGH", status: "OPEN" });

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get("/engagements/eng-a/findings/clusters").set("x-test-user", "admin@example.com").expect(200);

    expect(res.body.findings.map((f: any) => f.id)).toEqual(["still-open"]);
  });
});

describe("POST /engagements/:id/findings/query — natural-language search", () => {
  it("understood: false with no results when the provider isn't configured (default mock: null)", async () => {
    seedFinding({ id: "f-any", testId: "test-a", assetId: ASSET_ID, title: "Anything", severity: "LOW" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app)
      .post("/engagements/eng-a/findings/query")
      .set("x-test-user", "admin@example.com")
      .send({ question: "show me critical findings" })
      .expect(200);

    expect(res.body.understood).toBe(false);
    expect(res.body.findings).toEqual([]);
  });

  it("filters by the AI-interpreted severity/status, and returns the interpreted filter alongside results", async () => {
    seedFinding({ id: "f-critical-open", testId: "test-a", assetId: ASSET_ID, title: "SQLi", severity: "CRITICAL", status: "OPEN" });
    seedFinding({ id: "f-critical-fixed", testId: "test-a", assetId: ASSET_ID, title: "XSS", severity: "CRITICAL", status: "RETESTED_PASS" });
    seedFinding({ id: "f-low", testId: "test-a", assetId: ASSET_ID, title: "Verbose error", severity: "LOW", status: "OPEN" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    vi.mocked(nlQuery.translateQuery).mockResolvedValueOnce({ severity: ["CRITICAL"], status: ["OPEN"] });

    const res = await request(app)
      .post("/engagements/eng-a/findings/query")
      .set("x-test-user", "admin@example.com")
      .send({ question: "critical findings still open" })
      .expect(200);

    expect(res.body.understood).toBe(true);
    expect(res.body.interpretedFilter).toEqual({ severity: ["CRITICAL"], status: ["OPEN"] });
    expect(res.body.findings.map((f: any) => f.id)).toEqual(["f-critical-open"]);
  });

  it("filters by title substring (case-insensitive)", async () => {
    seedFinding({ id: "f-csp", testId: "test-a", assetId: ASSET_ID, title: "Missing CSP header", severity: "MEDIUM" });
    seedFinding({ id: "f-other", testId: "test-a", assetId: ASSET_ID, title: "Weak TLS config", severity: "MEDIUM" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    vi.mocked(nlQuery.translateQuery).mockResolvedValueOnce({ titleContains: "csp" });

    const res = await request(app)
      .post("/engagements/eng-a/findings/query")
      .set("x-test-user", "admin@example.com")
      .send({ question: "anything about CSP" })
      .expect(200);

    expect(res.body.findings.map((f: any) => f.id)).toEqual(["f-csp"]);
  });

  it("strips a hallucinated/unknown field rather than failing the whole interpretation", async () => {
    seedFinding({ id: "f-med", testId: "test-a", assetId: ASSET_ID, title: "Something", severity: "MEDIUM" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    vi.mocked(nlQuery.translateQuery).mockResolvedValueOnce({ severity: ["MEDIUM"], sqlWhereClause: "1=1; DROP TABLE finding;" });

    const res = await request(app)
      .post("/engagements/eng-a/findings/query")
      .set("x-test-user", "admin@example.com")
      .send({ question: "medium findings" })
      .expect(200);

    expect(res.body.understood).toBe(true);
    expect(res.body.interpretedFilter).toEqual({ severity: ["MEDIUM"] }); // hallucinated field silently dropped, not passed through
    expect(res.body.findings.map((f: any) => f.id)).toEqual(["f-med"]);
  });

  it("understood: false when the provider returns an invalid enum value", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    vi.mocked(nlQuery.translateQuery).mockResolvedValueOnce({ severity: ["SUPER_CRITICAL"] });

    const res = await request(app)
      .post("/engagements/eng-a/findings/query")
      .set("x-test-user", "admin@example.com")
      .send({ question: "super critical findings" })
      .expect(200);

    expect(res.body.understood).toBe(false);
  });

  it("400s an empty question", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/findings/query").set("x-test-user", "admin@example.com").send({ question: "" }).expect(400);
  });

  it("404s for a different org's engagement", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-b/findings/query")
      .set("x-test-user", "tech@acme.com")
      .send({ question: "anything" })
      .expect(404);
  });

  it("never returns findings from a different engagement even if the interpreted filter matches everything", async () => {
    seedFinding({ id: "f-in-a", testId: "test-a", assetId: ASSET_ID, title: "In eng-a", severity: "HIGH" });
    const assetB = "dddddddd-dddd-dddd-dddd-dddddddddddd";
    seedAsset({ id: assetB, engagementId: "eng-b", type: "WEB", name: "Other org site" });
    seedTest({ id: "test-b", engagementId: "eng-b", assetId: assetB, type: "MANUAL", testerId: "user_admin" });
    seedFinding({ id: "f-in-b", testId: "test-b", assetId: assetB, title: "In eng-b", severity: "HIGH" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    vi.mocked(nlQuery.translateQuery).mockResolvedValueOnce({ severity: ["HIGH"] }); // no engagement scoping in the filter itself — the route supplies that

    const res = await request(app)
      .post("/engagements/eng-a/findings/query")
      .set("x-test-user", "admin@example.com")
      .send({ question: "high severity findings" })
      .expect(200);

    expect(res.body.findings.map((f: any) => f.id)).toEqual(["f-in-a"]);
  });
});

import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEngagement, seedAsset, seedScanJob, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
  seedEngagement({ id: "eng-a", clientId: CLIENT_A, authorizationSignedAt: new Date() });
});

describe("POST /engagements/:id/assets/:assetId/scan — every safety gate", () => {
  it("403s for a non-admin role", async () => {
    seedAsset({ id: "asset-a", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post("/engagements/eng-a/assets/asset-a/scan").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("403s when the engagement has no signed authorization", async () => {
    seedEngagement({ id: "eng-unauth", clientId: CLIENT_A, authorizationSignedAt: null });
    seedAsset({ id: "asset-b", engagementId: "eng-unauth", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-unauth/assets/asset-b/scan").set("x-test-user", "admin@example.com").expect(403);
  });

  it("403s when the asset is marked out of scope", async () => {
    seedAsset({ id: "asset-c", engagementId: "eng-a", type: "WEB", name: "Site", inScope: false, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-c/scan").set("x-test-user", "admin@example.com").expect(403);
  });

  it("400s for a non-scannable asset type (e.g. NETWORK)", async () => {
    seedAsset({ id: "asset-d", engagementId: "eng-a", type: "NETWORK", name: "LAN", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-d/scan").set("x-test-user", "admin@example.com").expect(400);
  });

  it("403s when the asset hasn't proven ownership (VERIFIED) yet — the SSRF guard", async () => {
    seedAsset({ id: "asset-e", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "UNVERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-e/scan").set("x-test-user", "admin@example.com").expect(403);
  });

  it("409s when a scan is already running for that asset", async () => {
    seedAsset({ id: "asset-f", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedScanJob({ id: "job-1", engagementId: "eng-a", assetId: "asset-f", testId: "test-x", status: "RUNNING" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-f/scan").set("x-test-user", "admin@example.com").expect(409);
  });

  it("202s and queues a scan once every gate passes", async () => {
    seedAsset({ id: "asset-g", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).post("/engagements/eng-a/assets/asset-g/scan").set("x-test-user", "admin@example.com").expect(202);
    expect(res.body.status).toBe("QUEUED");
  });
});

describe("GET /scan-jobs/:id — cross-tenant IDOR protection + raw-result role gate", () => {
  it("404s when a client-role user requests a scan job from a DIFFERENT org", async () => {
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    seedAsset({ id: "asset-b", engagementId: "eng-b", type: "WEB", name: "Other" });
    seedScanJob({ id: "job-b", engagementId: "eng-b", assetId: "asset-b", testId: "test-b" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/scan-jobs/job-b").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("withholds rawResult from a technical_client (only SECURITY_ADMIN gets it, same tier as evidence)", async () => {
    seedAsset({ id: "asset-h", engagementId: "eng-a", type: "WEB", name: "Site" });
    seedScanJob({ id: "job-h", engagementId: "eng-a", assetId: "asset-h", testId: "test-h", rawResultEnc: { fake: "encrypted-blob" } });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    const res = await request(app).get("/scan-jobs/job-h").set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body.rawResult).toBeUndefined();
  });
});

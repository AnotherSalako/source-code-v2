import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import {
  seedUser,
  seedClient,
  seedEngagement,
  seedAsset,
  seedDiscoveryJob,
  seedDiscoveredAsset,
  resetFakeDb,
} from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();
// Real encryption (test-app.ts wires "../../src/crypto" to a real
// LocalKmsProvider) — needed because promote/ignore/list all decrypt
// DiscoveredAsset.valueEnc for real, not a role-gated skip like scan-jobs'
// rawResult.
const { kms } = await import("../../src/crypto");
const { encryptField } = await import("../../src/crypto/envelope");

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
  seedEngagement({ id: "eng-a", clientId: CLIENT_A, authorizationSignedAt: new Date() });
});

describe("POST /engagements/:id/assets/:assetId/discover — every safety gate", () => {
  it("403s for a non-admin role", async () => {
    seedAsset({ id: "asset-a", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post("/engagements/eng-a/assets/asset-a/discover").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("403s when the engagement has no signed authorization", async () => {
    seedEngagement({ id: "eng-unauth", clientId: CLIENT_A, authorizationSignedAt: null });
    seedAsset({ id: "asset-b", engagementId: "eng-unauth", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-unauth/assets/asset-b/discover").set("x-test-user", "admin@example.com").expect(403);
  });

  it("403s when the asset is marked out of scope", async () => {
    seedAsset({ id: "asset-c", engagementId: "eng-a", type: "WEB", name: "Site", inScope: false, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-c/discover").set("x-test-user", "admin@example.com").expect(403);
  });

  it("400s for a non-discoverable asset type (e.g. NETWORK)", async () => {
    seedAsset({ id: "asset-d", engagementId: "eng-a", type: "NETWORK", name: "LAN", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-d/discover").set("x-test-user", "admin@example.com").expect(400);
  });

  it("403s when the asset hasn't proven ownership (VERIFIED) yet — the same guard scanning uses", async () => {
    seedAsset({ id: "asset-e", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "UNVERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-e/discover").set("x-test-user", "admin@example.com").expect(403);
  });

  it("409s when a discovery run is already in progress for that asset", async () => {
    seedAsset({ id: "asset-f", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedDiscoveryJob({ id: "job-1", engagementId: "eng-a", assetId: "asset-f", status: "RUNNING" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-f/discover").set("x-test-user", "admin@example.com").expect(409);
  });

  it("202s and queues a discovery run once every gate passes", async () => {
    seedAsset({ id: "asset-g", engagementId: "eng-a", type: "WEB", name: "Site", inScope: true, verificationStatus: "VERIFIED" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).post("/engagements/eng-a/assets/asset-g/discover").set("x-test-user", "admin@example.com").expect(202);
    expect(res.body.status).toBe("QUEUED");
  });
});

describe("GET /engagements/:id/discovered-assets — cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a different org's engagement", async () => {
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/engagements/eng-b/discovered-assets").set("x-test-user", "tech@acme.com").expect(404);
  });
});

describe("POST /discovered-assets/:id/promote and /ignore", () => {
  it("promote creates a real (UNVERIFIED) Asset and marks the row PROMOTED", async () => {
    seedAsset({ id: "asset-h", engagementId: "eng-a", type: "WEB", name: "Root", verificationStatus: "VERIFIED" });
    seedDiscoveryJob({ id: "job-h", engagementId: "eng-a", assetId: "asset-h", status: "COMPLETE" });
    seedDiscoveredAsset({
      id: "disc-h",
      engagementId: "eng-a",
      parentAssetId: "asset-h",
      discoveryJobId: "job-h",
      valueEnc: (await encryptField(kms, "sub.acme.example", "discoveredAsset:value")) as any,
    });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).post("/discovered-assets/disc-h/promote").set("x-test-user", "admin@example.com").expect(201);
    expect(res.body.id).toBeTruthy();

    const list = await request(app).get("/engagements/eng-a/discovered-assets").set("x-test-user", "admin@example.com").expect(200);
    const promoted = list.body.find((d: any) => d.id === "disc-h");
    expect(promoted.status).toBe("PROMOTED");
    expect(promoted.promotedAssetId).toBe(res.body.id);
  });

  it("400s promoting a row that's already been reviewed", async () => {
    seedAsset({ id: "asset-i", engagementId: "eng-a", type: "WEB", name: "Root", verificationStatus: "VERIFIED" });
    seedDiscoveryJob({ id: "job-i", engagementId: "eng-a", assetId: "asset-i", status: "COMPLETE" });
    seedDiscoveredAsset({
      id: "disc-i",
      engagementId: "eng-a",
      parentAssetId: "asset-i",
      discoveryJobId: "job-i",
      valueEnc: (await encryptField(kms, "sub.acme.example", "discoveredAsset:value")) as any,
      status: "IGNORED",
    });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/discovered-assets/disc-i/promote").set("x-test-user", "admin@example.com").expect(400);
  });

  it("ignore marks the row IGNORED without creating an Asset", async () => {
    seedAsset({ id: "asset-j", engagementId: "eng-a", type: "WEB", name: "Root", verificationStatus: "VERIFIED" });
    seedDiscoveryJob({ id: "job-j", engagementId: "eng-a", assetId: "asset-j", status: "COMPLETE" });
    seedDiscoveredAsset({
      id: "disc-j",
      engagementId: "eng-a",
      parentAssetId: "asset-j",
      discoveryJobId: "job-j",
      valueEnc: (await encryptField(kms, "sub.acme.example", "discoveredAsset:value")) as any,
    });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    await request(app).post("/discovered-assets/disc-j/ignore").set("x-test-user", "admin@example.com").expect(200);

    const list = await request(app).get("/engagements/eng-a/discovered-assets").set("x-test-user", "admin@example.com").expect(200);
    expect(list.body.find((d: any) => d.id === "disc-j").status).toBe("IGNORED");
  });

  it("403s promote/ignore for a non-admin role", async () => {
    seedAsset({ id: "asset-k", engagementId: "eng-a", type: "WEB", name: "Root", verificationStatus: "VERIFIED" });
    seedDiscoveryJob({ id: "job-k", engagementId: "eng-a", assetId: "asset-k", status: "COMPLETE" });
    seedDiscoveredAsset({
      id: "disc-k",
      engagementId: "eng-a",
      parentAssetId: "asset-k",
      discoveryJobId: "job-k",
      valueEnc: (await encryptField(kms, "sub.acme.example", "discoveredAsset:value")) as any,
    });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post("/discovered-assets/disc-k/promote").set("x-test-user", "tech@acme.com").expect(403);
  });
});

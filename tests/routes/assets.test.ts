import request from "supertest";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { seedUser, seedClient, seedEngagement, seedAsset, resetFakeDb } from "../helpers/test-app";

vi.mock("../../src/modules/assets/verification", () => ({
  checkDnsTxt: vi.fn().mockResolvedValue(true),
  checkHttpFile: vi.fn().mockResolvedValue(true),
  generateVerificationToken: () => "test-token-123",
  WELL_KNOWN_PATH: "/.well-known/enforcer-verification",
}));

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

describe("POST /engagements/:id/assets", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/assets")
      .set("x-test-user", "tech@acme.com")
      .send({ type: "WEB", name: "Prod site", identifier: "https://acme.example" })
      .expect(403);
  });

  it("201s for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/engagements/eng-a/assets")
      .set("x-test-user", "admin@example.com")
      .send({ type: "WEB", name: "Prod site", identifier: "https://acme.example" })
      .expect(201);
    expect(res.body.name).toBe("Prod site");
  });
});

describe("GET /engagements/:id/assets — cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a different org's engagement's assets", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/engagements/eng-b/assets").set("x-test-user", "tech@acme.com").expect(404);
  });
});

describe("Asset ownership verification", () => {
  it("verification/start 404s when the asset belongs to a DIFFERENT engagement than the one in the URL (confused-deputy guard)", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedAsset({ id: "asset-1", engagementId: "eng-a", type: "WEB", name: "Site" });

    await request(app)
      .post("/engagements/eng-b/assets/asset-1/verification/start") // asset-1 belongs to eng-a, not eng-b
      .set("x-test-user", "admin@example.com")
      .send({ method: "DNS_TXT" })
      .expect(404);
  });

  it("full verification flow: start then check moves an asset to VERIFIED", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    // Created through the real endpoint (not seedAsset) so identifierEnc is
    // genuinely encrypted — verification/start decrypts it for real.
    const created = await request(app)
      .post("/engagements/eng-a/assets")
      .set("x-test-user", "admin@example.com")
      .send({ type: "WEB", name: "Site", identifier: "https://acme.example" })
      .expect(201);
    const assetId = created.body.id;

    await request(app)
      .post(`/engagements/eng-a/assets/${assetId}/verification/start`)
      .set("x-test-user", "admin@example.com")
      .send({ method: "DNS_TXT" })
      .expect(200);

    const res = await request(app)
      .post(`/engagements/eng-a/assets/${assetId}/verification/check`)
      .set("x-test-user", "admin@example.com")
      .expect(200);
    expect(res.body.verified).toBe(true);
  });

  it("manual verification requires a justification of at least 10 chars", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedAsset({ id: "asset-1", engagementId: "eng-a", type: "WEB", name: "Site" });

    await request(app)
      .post("/engagements/eng-a/assets/asset-1/verification/manual")
      .set("x-test-user", "admin@example.com")
      .send({ justification: "too short" })
      .expect(400);

    await request(app)
      .post("/engagements/eng-a/assets/asset-1/verification/manual")
      .set("x-test-user", "admin@example.com")
      .send({ justification: "Covered under the signed master ROE, section 4." })
      .expect(200);
  });
});

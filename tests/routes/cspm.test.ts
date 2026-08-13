import request from "supertest";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { seedUser, seedClient, seedCloudCredential, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();
const { runCspmScan, verifyCredentials } = await import("../../src/modules/cspm/cspm-scanner");
const { kms } = await import("../../src/crypto");
const { encryptField } = await import("../../src/crypto/envelope");

async function seedRealCloudCredential(clientId: string) {
  return seedCloudCredential(clientId, {
    accessKeyIdEnc: (await encryptField(kms, "AKIA_TEST", "cloudCredential:accessKeyId")) as any,
    secretAccessKeyEnc: (await encryptField(kms, "test-secret", "cloudCredential:secretAccessKey")) as any,
  });
}

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
});

describe("PUT /clients/:id/cloud-credentials", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .put(`/clients/${CLIENT_A}/cloud-credentials`)
      .set("x-test-user", "tech@acme.com")
      .send({ accessKeyId: "AKIA...", secretAccessKey: "secret", region: "us-east-1" })
      .expect(403);
  });

  it("400s a malformed body", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .put(`/clients/${CLIENT_A}/cloud-credentials`)
      .set("x-test-user", "admin@example.com")
      .send({ accessKeyId: "", secretAccessKey: "secret", region: "us-east-1" })
      .expect(400);
  });

  it("404s for a nonexistent client", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .put("/clients/does-not-exist/cloud-credentials")
      .set("x-test-user", "admin@example.com")
      .send({ accessKeyId: "AKIA...", secretAccessKey: "secret", region: "us-east-1" })
      .expect(404);
  });

  it("400s when the credentials don't actually authenticate against AWS", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    vi.mocked(verifyCredentials).mockResolvedValueOnce({ valid: false, error: "InvalidClientTokenId" });

    const res = await request(app)
      .put(`/clients/${CLIENT_A}/cloud-credentials`)
      .set("x-test-user", "admin@example.com")
      .send({ accessKeyId: "AKIA_FAKE", secretAccessKey: "secret", region: "us-east-1" })
      .expect(400);

    expect(res.body.error).toContain("InvalidClientTokenId");
  });

  it("stores real credentials on success and never echoes the secret back", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const putRes = await request(app)
      .put(`/clients/${CLIENT_A}/cloud-credentials`)
      .set("x-test-user", "admin@example.com")
      .send({ accessKeyId: "AKIA_REAL", secretAccessKey: "s3cr3t", region: "eu-west-1" })
      .expect(200);

    expect(putRes.body).toEqual({ configured: true, region: "eu-west-1" });
    expect(JSON.stringify(putRes.body)).not.toContain("s3cr3t");

    const getRes = await request(app).get(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body).toEqual({ configured: true, provider: "aws", region: "eu-west-1", lastScannedAt: null });
    expect(JSON.stringify(getRes.body)).not.toContain("s3cr3t");
  });

  it("upserts — a second PUT replaces the first credential rather than erroring", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .put(`/clients/${CLIENT_A}/cloud-credentials`)
      .set("x-test-user", "admin@example.com")
      .send({ accessKeyId: "AKIA_OLD", secretAccessKey: "old", region: "us-east-1" })
      .expect(200);

    const res = await request(app)
      .put(`/clients/${CLIENT_A}/cloud-credentials`)
      .set("x-test-user", "admin@example.com")
      .send({ accessKeyId: "AKIA_NEW", secretAccessKey: "new", region: "eu-west-2" })
      .expect(200);

    expect(res.body.region).toBe("eu-west-2");
  });
});

describe("GET /clients/:id/cloud-credentials", () => {
  it("reports configured: false when nothing is stored", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "admin@example.com").expect(200);
    expect(res.body).toEqual({ configured: false });
  });

  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "tech@acme.com").expect(403);
  });
});

describe("DELETE /clients/:id/cloud-credentials", () => {
  it("404s when nothing is configured", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).delete(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "admin@example.com").expect(404);
  });

  it("removes a configured credential", async () => {
    seedCloudCredential(CLIENT_A);
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    await request(app).delete(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "admin@example.com").expect(200);

    const getRes = await request(app).get(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body).toEqual({ configured: false });
  });
});

describe("POST /clients/:id/cspm-scan", () => {
  it("400s when no credentials are configured yet", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post(`/clients/${CLIENT_A}/cspm-scan`).set("x-test-user", "admin@example.com").expect(400);
  });

  it("403s for a non-admin role", async () => {
    seedCloudCredential(CLIENT_A);
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post(`/clients/${CLIENT_A}/cspm-scan`).set("x-test-user", "tech@acme.com").expect(403);
  });

  it("returns issues from the scanner and updates lastScannedAt", async () => {
    await seedRealCloudCredential(CLIENT_A);
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    vi.mocked(runCspmScan).mockResolvedValueOnce([
      { resourceType: "SECURITY_GROUP", resourceId: "sg-123", title: "Open to the world", severity: "HIGH", description: "..." },
    ]);

    const res = await request(app).post(`/clients/${CLIENT_A}/cspm-scan`).set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.issues).toHaveLength(1);
    expect(res.body.issues[0].resourceId).toBe("sg-123");

    const getRes = await request(app).get(`/clients/${CLIENT_A}/cloud-credentials`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body.lastScannedAt).toBeTruthy();
  });

  it("returns an empty issues array, not an error, when the scan finds nothing", async () => {
    await seedRealCloudCredential(CLIENT_A);
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const res = await request(app).post(`/clients/${CLIENT_A}/cspm-scan`).set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.issues).toEqual([]);
  });
});

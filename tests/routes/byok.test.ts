import request from "supertest";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { seedUser, seedClient, seedClientKmsCredential, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();
const { verifyKmsCredential } = await import("../../src/crypto/kms-verify");

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
});

describe("PUT /clients/:id/kms-credential", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .put(`/clients/${CLIENT_A}/kms-credential`)
      .set("x-test-user", "tech@acme.com")
      .send({ keyId: "arn:aws:kms:us-east-1:111:key/abc", region: "us-east-1", accessKeyId: "AKIA...", secretAccessKey: "secret" })
      .expect(403);
  });

  it("400s a malformed body", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .put(`/clients/${CLIENT_A}/kms-credential`)
      .set("x-test-user", "admin@example.com")
      .send({ keyId: "", region: "us-east-1", accessKeyId: "AKIA...", secretAccessKey: "secret" })
      .expect(400);
  });

  it("404s for a nonexistent client", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .put("/clients/does-not-exist/kms-credential")
      .set("x-test-user", "admin@example.com")
      .send({ keyId: "arn:aws:kms:us-east-1:111:key/abc", region: "us-east-1", accessKeyId: "AKIA...", secretAccessKey: "secret" })
      .expect(404);
  });

  it("400s when the credential can't GenerateDataKey/Decrypt against that key", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    vi.mocked(verifyKmsCredential).mockResolvedValueOnce({ valid: false, error: "AccessDeniedException" });

    const res = await request(app)
      .put(`/clients/${CLIENT_A}/kms-credential`)
      .set("x-test-user", "admin@example.com")
      .send({ keyId: "arn:aws:kms:us-east-1:111:key/wrong", region: "us-east-1", accessKeyId: "AKIA...", secretAccessKey: "wrong" })
      .expect(400);

    expect(res.body.error).toContain("AccessDeniedException");
  });

  it("stores real credentials on success and never echoes the secret back", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    const putRes = await request(app)
      .put(`/clients/${CLIENT_A}/kms-credential`)
      .set("x-test-user", "admin@example.com")
      .send({ keyId: "arn:aws:kms:us-east-1:111:key/real", region: "us-east-1", accessKeyId: "AKIA_REAL", secretAccessKey: "s3cr3t" })
      .expect(200);

    expect(putRes.body).toEqual({ configured: true, region: "us-east-1", keyId: "arn:aws:kms:us-east-1:111:key/real" });
    expect(JSON.stringify(putRes.body)).not.toContain("s3cr3t");

    const getRes = await request(app).get(`/clients/${CLIENT_A}/kms-credential`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body).toEqual({ configured: true, keyId: "arn:aws:kms:us-east-1:111:key/real", region: "us-east-1" });
    expect(JSON.stringify(getRes.body)).not.toContain("s3cr3t");
  });

  it("upserts — a second PUT replaces the first credential rather than erroring", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .put(`/clients/${CLIENT_A}/kms-credential`)
      .set("x-test-user", "admin@example.com")
      .send({ keyId: "arn:old", region: "us-east-1", accessKeyId: "old", secretAccessKey: "old" })
      .expect(200);

    const res = await request(app)
      .put(`/clients/${CLIENT_A}/kms-credential`)
      .set("x-test-user", "admin@example.com")
      .send({ keyId: "arn:new", region: "eu-west-2", accessKeyId: "new", secretAccessKey: "new" })
      .expect(200);

    expect(res.body.keyId).toBe("arn:new");
    expect(res.body.region).toBe("eu-west-2");
  });
});

describe("GET /clients/:id/kms-credential", () => {
  it("reports configured: false when nothing is stored", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get(`/clients/${CLIENT_A}/kms-credential`).set("x-test-user", "admin@example.com").expect(200);
    expect(res.body).toEqual({ configured: false });
  });

  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get(`/clients/${CLIENT_A}/kms-credential`).set("x-test-user", "tech@acme.com").expect(403);
  });
});

describe("DELETE /clients/:id/kms-credential", () => {
  it("404s when nothing is configured", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).delete(`/clients/${CLIENT_A}/kms-credential`).set("x-test-user", "admin@example.com").expect(404);
  });

  it("removes a configured credential", async () => {
    seedClientKmsCredential(CLIENT_A);
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });

    await request(app).delete(`/clients/${CLIENT_A}/kms-credential`).set("x-test-user", "admin@example.com").expect(200);

    const getRes = await request(app).get(`/clients/${CLIENT_A}/kms-credential`).set("x-test-user", "admin@example.com").expect(200);
    expect(getRes.body).toEqual({ configured: false });
  });
});

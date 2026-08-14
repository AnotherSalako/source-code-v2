import request from "supertest";
import crypto from "crypto";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEnrollmentToken, seedDevice, getUsageEvents, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/** Mirrors what the Rust agent does with ed25519-dalek: a raw 32-byte Ed25519 keypair, base64 on the wire. */
function generateDeviceKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubJwk = publicKey.export({ format: "jwk" }) as { x: string };
  const publicKeyBase64 = Buffer.from(pubJwk.x, "base64url").toString("base64");
  return { privateKey, publicKeyBase64 };
}

/** Mirrors device-auth.middleware.ts's expected signed payload exactly. */
function signRequest(privateKey: crypto.KeyObject, method: string, path: string, timestamp: number, body?: unknown): string {
  const bodyStr = body && Object.keys(body as object).length > 0 ? JSON.stringify(body) : "";
  const bodyHash = crypto.createHash("sha256").update(bodyStr, "utf8").digest("base64");
  const payload = `${method}.${path}.${timestamp}.${bodyHash}`;
  return crypto.sign(null, Buffer.from(payload, "utf8"), privateKey).toString("base64");
}

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
});

describe("POST /clients/:id/devices/enrollment-tokens", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post(`/clients/${CLIENT_A}/devices/enrollment-tokens`).set("x-test-user", "tech@acme.com").expect(403);
  });

  it("404s for a nonexistent client", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/clients/does-not-exist/devices/enrollment-tokens").set("x-test-user", "admin@example.com").expect(404);
  });

  it("201s and returns a plaintext token + expiry, once", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post(`/clients/${CLIENT_A}/devices/enrollment-tokens`)
      .set("x-test-user", "admin@example.com")
      .expect(201);
    expect(res.body.token).toBeTruthy();
    expect(new Date(res.body.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });
});

describe("POST /internal/agents/enroll", () => {
  it("400s on a malformed body", async () => {
    await request(app).post("/internal/agents/enroll").send({}).expect(400);
  });

  it("401s on an unknown token", async () => {
    const { publicKeyBase64 } = generateDeviceKeypair();
    await request(app)
      .post("/internal/agents/enroll")
      .send({ token: "does-not-exist", publicKeyBase64, hostname: "host-1", platform: "linux" })
      .expect(401);
  });

  it("401s on an expired token", async () => {
    seedEnrollmentToken({
      id: "tok-1",
      clientId: CLIENT_A,
      tokenHash: hashToken("expired-token"),
      createdBy: "admin-1",
      expiresAt: new Date(Date.now() - 1000),
    });
    const { publicKeyBase64 } = generateDeviceKeypair();
    await request(app)
      .post("/internal/agents/enroll")
      .send({ token: "expired-token", publicKeyBase64, hostname: "host-1", platform: "linux" })
      .expect(401);
  });

  it("401s on an already-used token", async () => {
    seedEnrollmentToken({
      id: "tok-2",
      clientId: CLIENT_A,
      tokenHash: hashToken("used-token"),
      createdBy: "admin-1",
      expiresAt: new Date(Date.now() + 100_000),
      usedAt: new Date(),
    });
    const { publicKeyBase64 } = generateDeviceKeypair();
    await request(app)
      .post("/internal/agents/enroll")
      .send({ token: "used-token", publicKeyBase64, hostname: "host-1", platform: "linux" })
      .expect(401);
  });

  it("201s on a valid token, returning a device identity and the CA's public key", async () => {
    seedEnrollmentToken({
      id: "tok-3",
      clientId: CLIENT_A,
      tokenHash: hashToken("valid-token"),
      createdBy: "admin-1",
      expiresAt: new Date(Date.now() + 100_000),
    });
    const { publicKeyBase64 } = generateDeviceKeypair();
    const res = await request(app)
      .post("/internal/agents/enroll")
      .send({ token: "valid-token", publicKeyBase64, hostname: "my-laptop", platform: "linux", osVersion: "Ubuntu 24.04" })
      .expect(201);
    expect(res.body.deviceId).toBeTruthy();
    expect(res.body.clientId).toBe(CLIENT_A);
    expect(res.body.credentialSignature).toBeTruthy();
    expect(res.body.caPublicKeyBase64).toBeTruthy();
  });

  it("a one-shot token cannot enroll a second device — the core security property", async () => {
    seedEnrollmentToken({
      id: "tok-4",
      clientId: CLIENT_A,
      tokenHash: hashToken("one-shot"),
      createdBy: "admin-1",
      expiresAt: new Date(Date.now() + 100_000),
    });
    const a = generateDeviceKeypair();
    const b = generateDeviceKeypair();
    await request(app)
      .post("/internal/agents/enroll")
      .send({ token: "one-shot", publicKeyBase64: a.publicKeyBase64, hostname: "host-a", platform: "linux" })
      .expect(201);
    await request(app)
      .post("/internal/agents/enroll")
      .send({ token: "one-shot", publicKeyBase64: b.publicKeyBase64, hostname: "host-b", platform: "windows" })
      .expect(401);
  });
});

describe("GET /clients/:id/devices and PATCH /devices/:id/revoke", () => {
  it("404s listing devices for a different org", async () => {
    seedUser({ email: "tech@beta.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_B });
    await request(app).get(`/clients/${CLIENT_A}/devices`).set("x-test-user", "tech@beta.com").expect(404);
  });

  it("lists devices for the caller's own org", async () => {
    seedDevice({ id: "dev-1", clientId: CLIENT_A, name: "laptop-1", publicKeyBase64: "abc" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    const res = await request(app).get(`/clients/${CLIENT_A}/devices`).set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].id).toBe("dev-1");
  });

  it("403s revoke for a non-admin", async () => {
    seedDevice({ id: "dev-2", clientId: CLIENT_A, name: "laptop-2", publicKeyBase64: "abc" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).patch("/devices/dev-2/revoke").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("revokes a device", async () => {
    seedDevice({ id: "dev-3", clientId: CLIENT_A, name: "laptop-3", publicKeyBase64: "abc" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).patch("/devices/dev-3/revoke").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.status).toBe("REVOKED");
  });
});

describe("GET /internal/agents/whoami — device-signed request auth", () => {
  it("401s with no auth headers", async () => {
    await request(app).get("/internal/agents/whoami").expect(401);
  });

  it("401s with an unknown deviceId", async () => {
    const { privateKey } = generateDeviceKeypair();
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(privateKey, "GET", "/internal/agents/whoami", timestamp);
    await request(app)
      .get("/internal/agents/whoami")
      .set("x-jupiter-device-id", "does-not-exist")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .expect(401);
  });

  it("401s a revoked device even with a correctly-computed signature", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-revoked", clientId: CLIENT_A, name: "x", publicKeyBase64, status: "REVOKED" });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(privateKey, "GET", "/internal/agents/whoami", timestamp);
    await request(app)
      .get("/internal/agents/whoami")
      .set("x-jupiter-device-id", "dev-revoked")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .expect(401);
  });

  it("401s a stale timestamp outside the replay window, even with a correct signature", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-stale", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const staleTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
    const signature = signRequest(privateKey, "GET", "/internal/agents/whoami", staleTimestamp);
    await request(app)
      .get("/internal/agents/whoami")
      .set("x-jupiter-device-id", "dev-stale")
      .set("x-jupiter-timestamp", String(staleTimestamp))
      .set("x-jupiter-signature", signature)
      .expect(401);
  });

  it("401s a tampered/invalid signature", async () => {
    const { publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-tampered", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    await request(app)
      .get("/internal/agents/whoami")
      .set("x-jupiter-device-id", "dev-tampered")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", Buffer.from("not-a-real-signature").toString("base64"))
      .expect(401);
  });

  it("401s a signature made with a DIFFERENT device's key (proves verification is actually keyed per-device)", async () => {
    const owner = generateDeviceKeypair();
    const attacker = generateDeviceKeypair();
    seedDevice({ id: "dev-owner", clientId: CLIENT_A, name: "x", publicKeyBase64: owner.publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(attacker.privateKey, "GET", "/internal/agents/whoami", timestamp);
    await request(app)
      .get("/internal/agents/whoami")
      .set("x-jupiter-device-id", "dev-owner")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .expect(401);
  });

  it("200s and returns the device identity for a correctly signed request, and records the check-in", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-good", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(privateKey, "GET", "/internal/agents/whoami", timestamp);
    const res = await request(app)
      .get("/internal/agents/whoami")
      .set("x-jupiter-device-id", "dev-good")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .expect(200);
    expect(res.body.deviceId).toBe("dev-good");
    expect(res.body.clientId).toBe(CLIENT_A);
  });
});

const SAMPLE_INVENTORY = {
  os: { name: "Ubuntu", version: "24.04" },
  software: [{ name: "openssh-server", version: "1:9.6p1-3ubuntu13" }],
  processes: [{ name: "sshd" }, { name: "nginx" }],
  firewall: "ENABLED" as const,
  interfaces: [{ name: "eth0", ip: "10.0.0.5" }],
  collectedAt: 1_700_000_000,
};

describe("POST /internal/agents/checkin — inventory check-in", () => {
  it("401s with no device auth headers", async () => {
    await request(app).post("/internal/agents/checkin").send(SAMPLE_INVENTORY).expect(401);
  });

  it("400s on a malformed inventory body", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-checkin-bad", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    const body = { os: { name: "Ubuntu" } }; // missing required fields
    const signature = signRequest(privateKey, "POST", "/internal/agents/checkin", timestamp, body);
    await request(app)
      .post("/internal/agents/checkin")
      .set("x-jupiter-device-id", "dev-checkin-bad")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .send(body)
      .expect(400);
  });

  it("401s a revoked device even with a valid signature and body", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-checkin-revoked", clientId: CLIENT_A, name: "x", publicKeyBase64, status: "REVOKED" });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(privateKey, "POST", "/internal/agents/checkin", timestamp, SAMPLE_INVENTORY);
    await request(app)
      .post("/internal/agents/checkin")
      .set("x-jupiter-device-id", "dev-checkin-revoked")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .send(SAMPLE_INVENTORY)
      .expect(401);
  });

  it("200s on a valid signed check-in and records osVersion + lastCheckInAt", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-checkin-ok", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(privateKey, "POST", "/internal/agents/checkin", timestamp, SAMPLE_INVENTORY);
    const res = await request(app)
      .post("/internal/agents/checkin")
      .set("x-jupiter-device-id", "dev-checkin-ok")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .send(SAMPLE_INVENTORY)
      .expect(200);
    expect(res.body.received).toBe(true);

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const devices = await request(app).get(`/clients/${CLIENT_A}/devices`).set("x-test-user", "admin@example.com").expect(200);
    const device = devices.body.find((d: any) => d.id === "dev-checkin-ok");
    expect(device.osVersion).toBe("Ubuntu 24.04");
    expect(device.lastCheckInAt).toBeTruthy();

    const events = getUsageEvents();
    expect(events.some((e) => e.clientId === CLIENT_A && e.kind === "AGENT_CHECK_IN")).toBe(true);
  });

  it("rejects a signature made over a different body than the one actually sent", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-checkin-tamper", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    // Sign one payload, send a different one — the body-hash mismatch must fail verification.
    const signature = signRequest(privateKey, "POST", "/internal/agents/checkin", timestamp, SAMPLE_INVENTORY);
    const tamperedBody = { ...SAMPLE_INVENTORY, os: { name: "Windows", version: "11" } };
    await request(app)
      .post("/internal/agents/checkin")
      .set("x-jupiter-device-id", "dev-checkin-tamper")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .send(tamperedBody)
      .expect(401);
  });
});

describe("GET /devices/:id/inventory", () => {
  it("403s for a non-admin role", async () => {
    seedDevice({ id: "dev-inv-1", clientId: CLIENT_A, name: "x", publicKeyBase64: "abc" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/devices/dev-inv-1/inventory").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("404s for a nonexistent device", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).get("/devices/does-not-exist/inventory").set("x-test-user", "admin@example.com").expect(404);
  });

  it("returns null inventory before any check-in has happened", async () => {
    seedDevice({ id: "dev-inv-3", clientId: CLIENT_A, name: "x", publicKeyBase64: "abc" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get("/devices/dev-inv-3/inventory").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.inventory).toBeNull();
  });

  it("returns the real decrypted inventory after a genuine check-in round trip", async () => {
    const { privateKey, publicKeyBase64 } = generateDeviceKeypair();
    seedDevice({ id: "dev-inv-4", clientId: CLIENT_A, name: "x", publicKeyBase64 });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = signRequest(privateKey, "POST", "/internal/agents/checkin", timestamp, SAMPLE_INVENTORY);
    await request(app)
      .post("/internal/agents/checkin")
      .set("x-jupiter-device-id", "dev-inv-4")
      .set("x-jupiter-timestamp", String(timestamp))
      .set("x-jupiter-signature", signature)
      .send(SAMPLE_INVENTORY)
      .expect(200);

    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).get("/devices/dev-inv-4/inventory").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body.inventory).toEqual(SAMPLE_INVENTORY);
    expect(res.body.collectedAt).toBeTruthy();
  });
});

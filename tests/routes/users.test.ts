import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

beforeEach(() => {
  resetFakeDb();
});

describe("GET /users", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });
    await request(app).get("/users").set("x-test-user", "tech@acme.com").expect(403);
  });

  it("200s and lists team members for an admin", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });

    const res = await request(app).get("/users").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body).toHaveLength(2);
  });
});

describe("POST /users", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });
    await request(app)
      .post("/users")
      .set("x-test-user", "tech@acme.com")
      .send({ name: "New", email: "new@acme.com", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" })
      .expect(403);
  });

  it("400s on an invalid email", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/users")
      .set("x-test-user", "admin@example.com")
      .send({ name: "New", email: "not-an-email", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" })
      .expect(400);
  });

  it("400s when a client role is created with no orgId", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/users")
      .set("x-test-user", "admin@example.com")
      .send({ name: "New", email: "new@acme.com", role: "TECHNICAL_CLIENT" })
      .expect(400);
  });

  it("409s when the email already has a User row", async () => {
    seedUser({ email: "existing@acme.com", name: "Existing", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/users")
      .set("x-test-user", "admin@example.com")
      .send({ name: "Dup", email: "existing@acme.com", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" })
      .expect(409);
  });

  it("201s, and normalizes a whitespace-padded/mixed-case email to trimmed lowercase (regression test for the uniqueness-bypass fix this session)", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/users")
      .set("x-test-user", "admin@example.com")
      .send({ name: "  New Hire  ", email: "  New.Hire@ACME.com  ", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" })
      .expect(201);
    expect(res.body.email).toBe("new.hire@acme.com");
    expect(res.body.name).toBe("New Hire");
  });
});

describe("DELETE /users/:id", () => {
  it("403s for a non-admin role", async () => {
    const target = seedUser({ email: "target@acme.com", name: "Target", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });
    await request(app).delete(`/users/${target.id}`).set("x-test-user", "tech@acme.com").expect(403);
  });

  it("400s when an admin tries to remove their own access", async () => {
    const admin = seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).delete(`/users/${admin.id}`).set("x-test-user", "admin@example.com").expect(400);
  });

  it("404s for a nonexistent user id", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).delete("/users/does-not-exist").set("x-test-user", "admin@example.com").expect(404);
  });

  it("204s and removes a different user's access", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const target = seedUser({ email: "target@acme.com", name: "Target", role: "TECHNICAL_CLIENT", orgId: "11111111-1111-1111-1111-111111111111" });
    await request(app).delete(`/users/${target.id}`).set("x-test-user", "admin@example.com").expect(204);
  });
});

import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEngagement, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
});

describe("POST /engagements", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).post("/engagements").set("x-test-user", "tech@acme.com").send({ clientId: CLIENT_A }).expect(403);
  });

  it("400s on a non-UUID clientId", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements").set("x-test-user", "admin@example.com").send({ clientId: "not-a-uuid" }).expect(400);
  });

  it("201s for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app).post("/engagements").set("x-test-user", "admin@example.com").send({ clientId: CLIENT_A }).expect(201);
    expect(res.body.clientId).toBe(CLIENT_A);
    expect(res.body.status).toBe("SCOPING");
  });
});

describe("GET /engagements — org scoping", () => {
  it("a client-role user only ever sees their own org's engagements, even when passing another org's clientId filter", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    seedEngagement({ id: "eng-a", clientId: CLIENT_A });
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });

    const res = await request(app).get(`/engagements?clientId=${CLIENT_B}`).set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body).toEqual([]); // asking for someone else's org returns nothing, not their own org's data either
  });

  it("SECURITY_ADMIN sees every engagement", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedEngagement({ id: "eng-a", clientId: CLIENT_A });
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });

    const res = await request(app).get("/engagements").set("x-test-user", "admin@example.com").expect(200);
    expect(res.body).toHaveLength(2);
  });
});

describe("GET /engagements/:id — cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a different org's engagement by ID", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    await request(app).get("/engagements/eng-b").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("200s for the caller's own org's engagement", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    seedEngagement({ id: "eng-a", clientId: CLIENT_A });
    await request(app).get("/engagements/eng-a").set("x-test-user", "tech@acme.com").expect(200);
  });
});

describe("POST /engagements/:id/authorize — the hard gate before any testing", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    seedEngagement({ id: "eng-a", clientId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/authorize")
      .set("x-test-user", "tech@acme.com")
      .send({ authorizedBy: "Someone", authorizationDocRef: "docs/roe.pdf" })
      .expect(403);
  });

  it("201s and flips the engagement to ACTIVE for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    seedEngagement({ id: "eng-a", clientId: CLIENT_A });
    const res = await request(app)
      .post("/engagements/eng-a/authorize")
      .set("x-test-user", "admin@example.com")
      .send({ authorizedBy: "Jane Doe", authorizationDocRef: "docs/roe.pdf" })
      .expect(200);
    expect(res.body.status).toBe("ACTIVE");
    expect(res.body.authorizationSignedAt).toBeTruthy();
  });
});

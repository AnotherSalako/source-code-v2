import request from "supertest";
import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, seedClient, seedEngagement, seedTrainingSession, resetFakeDb } from "../helpers/test-app";

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

describe("POST /engagements/:id/training-sessions", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/training-sessions")
      .set("x-test-user", "tech@acme.com")
      .send({ topic: "PHISHING", scheduledAt: new Date().toISOString() })
      .expect(403);
  });

  it("400s when topic is CUSTOM but customTopic is missing", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/engagements/eng-a/training-sessions")
      .set("x-test-user", "admin@example.com")
      .send({ topic: "CUSTOM", scheduledAt: new Date().toISOString() })
      .expect(400);
  });

  it("201s for a valid admin request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/engagements/eng-a/training-sessions")
      .set("x-test-user", "admin@example.com")
      .send({ topic: "PHISHING", scheduledAt: new Date().toISOString() })
      .expect(201);
    expect(res.body.topic).toBe("PHISHING");
  });
});

describe("GET /training-sessions/:id — cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a session from a DIFFERENT org", async () => {
    seedTrainingSession({ id: "session-b", engagementId: "eng-b", topic: "PHISHING" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/training-sessions/session-b").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("200s for the caller's own org's session", async () => {
    seedTrainingSession({ id: "session-a", engagementId: "eng-a", topic: "PHISHING" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/training-sessions/session-a").set("x-test-user", "tech@acme.com").expect(200);
  });
});

describe("PATCH /training-sessions/:id", () => {
  it("403s for a non-admin role", async () => {
    seedTrainingSession({ id: "session-a", engagementId: "eng-a", topic: "PHISHING" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .patch("/training-sessions/session-a")
      .set("x-test-user", "tech@acme.com")
      .send({ status: "COMPLETED" })
      .expect(403);
  });

  it("200s and updates status for an admin", async () => {
    seedTrainingSession({ id: "session-a", engagementId: "eng-a", topic: "PHISHING" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .patch("/training-sessions/session-a")
      .set("x-test-user", "admin@example.com")
      .send({ status: "COMPLETED" })
      .expect(200);
    expect(res.body.status).toBe("COMPLETED");
  });
});

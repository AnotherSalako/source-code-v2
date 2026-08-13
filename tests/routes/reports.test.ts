import request from "supertest";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { seedUser, seedClient, seedEngagement, seedReport, resetFakeDb } from "../helpers/test-app";

// buildReportContent walks the full engagement/findings graph to render a
// PDF — real report generation is covered elsewhere; here we're testing the
// route's auth/role/IDOR behavior, so the content itself is stubbed.
vi.mock("../../src/modules/reports/report.builder", () => ({
  buildReportContent: vi.fn().mockResolvedValue(Buffer.from("%PDF-1.4 fake report content")),
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
});

describe("POST /engagements/:id/reports/generate", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/reports/generate")
      .set("x-test-user", "tech@acme.com")
      .send({ type: "TECHNICAL" })
      .expect(403);
  });

  it("201s, and a second generate call for the same type increments the version", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const first = await request(app)
      .post("/engagements/eng-a/reports/generate")
      .set("x-test-user", "admin@example.com")
      .send({ type: "TECHNICAL" })
      .expect(201);
    expect(first.body.version).toBe(1);

    const second = await request(app)
      .post("/engagements/eng-a/reports/generate")
      .set("x-test-user", "admin@example.com")
      .send({ type: "TECHNICAL" })
      .expect(201);
    expect(second.body.version).toBe(2);
  });
});

describe("GET /engagements/:id/reports — EXEC_CLIENT only sees EXECUTIVE reports", () => {
  it("filters TECHNICAL reports out of the list for an EXEC_CLIENT", async () => {
    seedReport({ id: "report-tech", engagementId: "eng-a", type: "TECHNICAL" });
    seedReport({ id: "report-exec", engagementId: "eng-a", type: "EXECUTIVE" });
    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: CLIENT_A });

    const res = await request(app).get("/engagements/eng-a/reports").set("x-test-user", "exec@acme.com").expect(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].type).toBe("EXECUTIVE");
  });

  it("technical_client sees both types", async () => {
    seedReport({ id: "report-tech", engagementId: "eng-a", type: "TECHNICAL" });
    seedReport({ id: "report-exec", engagementId: "eng-a", type: "EXECUTIVE" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });

    const res = await request(app).get("/engagements/eng-a/reports").set("x-test-user", "tech@acme.com").expect(200);
    expect(res.body).toHaveLength(2);
  });
});

describe("GET /reports/:id/download — role gate + cross-tenant IDOR protection", () => {
  it("404s when a client-role user requests a DIFFERENT org's report", async () => {
    seedEngagement({ id: "eng-b", clientId: CLIENT_B });
    seedReport({ id: "report-b", engagementId: "eng-b", type: "TECHNICAL" });
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app).get("/reports/report-b/download").set("x-test-user", "tech@acme.com").expect(404);
  });

  it("403s when EXEC_CLIENT requests a non-EXECUTIVE report, even for their own org", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const generated = await request(app)
      .post("/engagements/eng-a/reports/generate")
      .set("x-test-user", "admin@example.com")
      .send({ type: "TECHNICAL" })
      .expect(201);

    seedUser({ email: "exec@acme.com", name: "Exec", role: "EXEC_CLIENT", orgId: CLIENT_A });
    await request(app).get(`/reports/${generated.body.id}/download`).set("x-test-user", "exec@acme.com").expect(403);
  });

  it("200s and streams the PDF for a valid same-org technical_client request", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const generated = await request(app)
      .post("/engagements/eng-a/reports/generate")
      .set("x-test-user", "admin@example.com")
      .send({ type: "TECHNICAL" })
      .expect(201);

    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    const res = await request(app).get(`/reports/${generated.body.id}/download`).set("x-test-user", "tech@acme.com").expect(200);
    expect(res.headers["content-type"]).toBe("application/pdf");
  });
});

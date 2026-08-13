import { describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

// requireRole audit-logs denials via the real `prisma` singleton — mock it
// so these stay unit tests, not integration tests against a live DB.
vi.mock("../src/db/prisma", () => ({
  prisma: { auditLog: { create: vi.fn().mockResolvedValue({}) } },
}));

const { assertOwnOrg, requireRole } = await import("../src/middleware/rbac");

function fakeReq(user: { id: string; role: "SECURITY_ADMIN" | "TECHNICAL_CLIENT" | "EXEC_CLIENT"; orgId: string | null } | undefined): Request {
  return {
    user,
    ip: "127.0.0.1",
    headers: {},
    baseUrl: "",
    path: "/test",
  } as unknown as Request;
}

function fakeRes(): Response {
  const res: Partial<Response> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as Response;
}

describe("assertOwnOrg", () => {
  it("denies when there is no authenticated user", () => {
    expect(assertOwnOrg(fakeReq(undefined), "client-1")).toBe(false);
  });

  it("allows SECURITY_ADMIN regardless of the target client", () => {
    const req = fakeReq({ id: "u1", role: "SECURITY_ADMIN", orgId: null });
    expect(assertOwnOrg(req, "any-client-id")).toBe(true);
  });

  it("allows a client user whose orgId matches the target client", () => {
    const req = fakeReq({ id: "u2", role: "TECHNICAL_CLIENT", orgId: "client-1" });
    expect(assertOwnOrg(req, "client-1")).toBe(true);
  });

  it("denies a client user whose orgId belongs to a different client (the IDOR class of bug fixed in findings/evidence/compliance/reports/retests this session)", () => {
    const req = fakeReq({ id: "u3", role: "EXEC_CLIENT", orgId: "client-1" });
    expect(assertOwnOrg(req, "client-2")).toBe(false);
  });

  it("denies a client user with no orgId set at all", () => {
    const req = fakeReq({ id: "u4", role: "TECHNICAL_CLIENT", orgId: null });
    expect(assertOwnOrg(req, "client-1")).toBe(false);
  });
});

describe("requireRole", () => {
  it("calls next() when the user has one of the allowed roles", async () => {
    const middleware = requireRole("SECURITY_ADMIN");
    const req = fakeReq({ id: "u1", role: "SECURITY_ADMIN", orgId: null });
    const res = fakeRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("denies with 403 when the user's role isn't in the allowed list", async () => {
    const middleware = requireRole("SECURITY_ADMIN");
    const req = fakeReq({ id: "u2", role: "EXEC_CLIENT", orgId: "client-1" });
    const res = fakeRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("denies with 403 when there is no authenticated user at all", async () => {
    const middleware = requireRole("SECURITY_ADMIN");
    const req = fakeReq(undefined);
    const res = fakeRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("allows access when any one of multiple allowed roles matches", async () => {
    const middleware = requireRole("SECURITY_ADMIN", "TECHNICAL_CLIENT");
    const req = fakeReq({ id: "u5", role: "TECHNICAL_CLIENT", orgId: "client-1" });
    const res = fakeRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });
});

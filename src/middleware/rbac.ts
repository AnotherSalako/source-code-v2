import { NextFunction, Request, Response } from "express";
import { Role } from "@prisma/client";
import { writeAuditLog } from "../modules/audit/audit.service";
import { prisma } from "../db/prisma";

/** Restricts a route to the given roles. Denials are audit-logged, not just 403'd. */
export function requireRole(...roles: Role[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user || !roles.includes(req.user.role)) {
      await writeAuditLog(prisma, {
        userId: req.user?.id ?? null,
        action: "VIEW",
        resourceType: req.baseUrl + req.path,
        resourceId: null,
        result: "DENIED",
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"] ?? null,
      });
      res.status(403).json({ error: "Insufficient role for this resource" });
      return;
    }
    next();
  };
}

/**
 * Client-side roles (EXEC_CLIENT, TECHNICAL_CLIENT) may only ever reach data
 * scoped to their own orgId. SECURITY_ADMIN (internal staff) is exempt.
 * Call after requireAuth, with the target engagement/client's clientId.
 */
export function assertOwnOrg(req: Request, clientId: string): boolean {
  if (!req.user) return false;
  if (req.user.role === "SECURITY_ADMIN") return true;
  return req.user.orgId === clientId;
}

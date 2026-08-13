import { Router } from "express";
import { prisma } from "../../db/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";

export const auditRouter = Router();

auditRouter.get("/", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const { resourceType, resourceId, userId, limit } = req.query;
  const logs = await prisma.auditLog.findMany({
    where: {
      resourceType: typeof resourceType === "string" ? resourceType : undefined,
      resourceId: typeof resourceId === "string" ? resourceId : undefined,
      userId: typeof userId === "string" ? userId : undefined,
    },
    orderBy: { timestamp: "desc" },
    take: Math.min(parseInt(String(limit ?? "100"), 10) || 100, 500),
  });
  res.json(logs);
});

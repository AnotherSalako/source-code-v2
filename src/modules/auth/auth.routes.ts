import { Router } from "express";
import { prisma } from "../../db/prisma";
import { requireAuth } from "../../middleware/auth";

export const authRouter = Router();

// Login, password reset, and MFA are all handled by Clerk on the frontend
// now — there's no server-side login endpoint here anymore. This just
// confirms who the Clerk-verified caller resolves to in our own User table
// (see src/middleware/auth.ts for how requireAuth bridges the two).
authRouter.get("/me", requireAuth, async (req, res) => {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
  res.json({ id: user.id, name: user.name, role: user.role, orgId: user.orgId });
});

import { Router } from "express";
import { z } from "zod";
import { TestType } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";

export const testsRouter = Router({ mergeParams: true });

testsRouter.get("/engagements/:engagementId/tests", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const tests = await prisma.test.findMany({ where: { engagementId } });
  res.json(tests);
});

const createSchema = z.object({
  assetId: z.string().uuid(),
  type: z.nativeEnum(TestType),
  methodology: z.string().optional(),
  toolUsed: z.string().optional(),
});

// Hard gate mirroring engagements.authorize: no test record can be created
// until the engagement has a signed authorization on file.
testsRouter.post("/engagements/:engagementId/tests", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { engagementId } = req.params;

  const engagement = await prisma.engagement.findUnique({ where: { id: engagementId } });
  if (!engagement) {
    res.status(404).json({ error: "Engagement not found" });
    return;
  }
  if (!engagement.authorizationSignedAt) {
    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "test",
      resourceId: null,
      engagementId,
      result: "DENIED",
    });
    res.status(403).json({
      error: "Engagement is not authorized yet. POST /engagements/:id/authorize first.",
    });
    return;
  }

  const test = await prisma.test.create({
    data: {
      engagementId,
      assetId: parsed.data.assetId,
      type: parsed.data.type,
      methodology: parsed.data.methodology,
      toolUsed: parsed.data.toolUsed,
      testerId: req.user!.id,
      status: "PLANNED",
    },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "CREATE",
    resourceType: "test",
    resourceId: test.id,
    engagementId,
    result: "SUCCESS",
  });

  res.status(201).json(test);
});

const patchSchema = z.object({
  status: z.enum(["PLANNED", "IN_PROGRESS", "COMPLETE"]).optional(),
  completedAt: z.coerce.date().optional(),
});

testsRouter.patch("/engagements/:engagementId/tests/:testId", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const updated = await prisma.test.update({
    where: { id: req.params.testId },
    data: parsed.data,
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "UPDATE",
    resourceType: "test",
    resourceId: updated.id,
    engagementId: req.params.engagementId,
    result: "SUCCESS",
  });

  res.json(updated);
});

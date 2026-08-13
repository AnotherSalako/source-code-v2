import { Router } from "express";
import { z } from "zod";
import { TrainingStatus, TrainingTopic } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";

export const trainingRouter = Router({ mergeParams: true });

const createSchema = z
  .object({
    topic: z.nativeEnum(TrainingTopic),
    customTopic: z.string().trim().max(200).optional(),
    scheduledAt: z.coerce.date(),
    notes: z.string().max(10_000).optional(),
  })
  .refine((data) => data.topic !== "CUSTOM" || !!data.customTopic, {
    message: "customTopic is required when topic is CUSTOM",
    path: ["customTopic"],
  });

trainingRouter.post(
  "/engagements/:engagementId/training-sessions",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId } = req.params;
    const t = parsed.data;

    const session = await prisma.trainingSession.create({
      data: {
        engagementId,
        topic: t.topic,
        customTopic: t.topic === "CUSTOM" ? t.customTopic : undefined,
        scheduledAt: t.scheduledAt,
        notesEnc: t.notes ? ((await encryptField(kms, t.notes, `training:notes`)) as any) : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "trainingSession",
      resourceId: session.id,
      engagementId,
      result: "SUCCESS",
    });

    res.status(201).json({ id: session.id, topic: session.topic, scheduledAt: session.scheduledAt });
  }
);

trainingRouter.get("/engagements/:engagementId/training-sessions", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const sessions = await prisma.trainingSession.findMany({
    where: { engagementId },
    select: {
      id: true,
      topic: true,
      customTopic: true,
      scheduledAt: true,
      status: true,
      attendeeCount: true,
    },
    orderBy: { scheduledAt: "asc" },
  });

  res.json(sessions);
});

const updateSchema = z.object({
  status: z.nativeEnum(TrainingStatus).optional(),
  scheduledAt: z.coerce.date().optional(),
  attendeeCount: z.number().int().min(0).optional(),
  notes: z.string().max(10_000).optional(),
});

trainingRouter.patch(
  "/training-sessions/:id",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = updateSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const session = await prisma.trainingSession.findUnique({
      where: { id: req.params.id },
      include: { engagement: { select: { clientId: true } } },
    });
    if (!session || !assertOwnOrg(req, session.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const updated = await prisma.trainingSession.update({
      where: { id: session.id },
      data: {
        status: parsed.data.status,
        scheduledAt: parsed.data.scheduledAt,
        attendeeCount: parsed.data.attendeeCount,
        notesEnc: parsed.data.notes ? ((await encryptField(kms, parsed.data.notes, `training:notes`)) as any) : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "trainingSession",
      resourceId: updated.id,
      engagementId: session.engagementId,
      result: "SUCCESS",
    });

    res.json({ id: updated.id, status: updated.status });
  }
);

trainingRouter.get("/training-sessions/:id", requireAuth, async (req, res) => {
  const session = await prisma.trainingSession.findUnique({
    where: { id: req.params.id },
    include: { engagement: { select: { clientId: true } } },
  });
  if (!session || !assertOwnOrg(req, session.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "trainingSession",
    resourceId: session.id,
    engagementId: session.engagementId,
    result: "SUCCESS",
  });

  const notes = session.notesEnc ? await decryptField(kms, session.notesEnc as any, `training:notes`) : undefined;

  res.json({
    id: session.id,
    topic: session.topic,
    customTopic: session.customTopic,
    scheduledAt: session.scheduledAt,
    status: session.status,
    attendeeCount: session.attendeeCount,
    notes,
  });
});

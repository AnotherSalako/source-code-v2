import { Router } from "express";
import { z } from "zod";
import { ComplianceFramework, ComplianceStatus } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { encryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { CONTROL_LIBRARY } from "./control-library";

export const complianceRouter = Router({ mergeParams: true });

const createSchema = z.object({
  framework: z.nativeEnum(ComplianceFramework),
  controlId: z.string().trim().min(1).max(100),
  controlName: z.string().trim().min(1).max(300),
  status: z.nativeEnum(ComplianceStatus),
  notes: z.string().max(10_000).optional(),
});

complianceRouter.post(
  "/engagements/:engagementId/compliance-checks",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId } = req.params;
    const c = parsed.data;

    const check = await prisma.complianceCheck.create({
      data: {
        engagementId,
        framework: c.framework,
        controlId: c.controlId,
        controlName: c.controlName,
        status: c.status,
        notesEnc: c.notes ? ((await encryptField(kms, c.notes, `compliance:notes`)) as any) : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "complianceCheck",
      resourceId: check.id,
      engagementId,
      result: "SUCCESS",
    });

    res.status(201).json(check);
  }
);

// Loads a standard control set (ISO27001's full Annex A, or an NDPA/NDPR-
// derived checklist) as PENDING checks, so a consultant reviews and assesses
// each one instead of typing dozens of controls in by hand. Idempotent per
// engagement+framework+controlId — safe to click again without duplicating.
const seedSchema = z.object({ framework: z.nativeEnum(ComplianceFramework) });

complianceRouter.post(
  "/engagements/:engagementId/compliance-checks/seed",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = seedSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId } = req.params;
    const { framework } = parsed.data;
    const library = CONTROL_LIBRARY[framework];
    if (!library) {
      res.status(400).json({ error: `No standard control library available for ${framework}` });
      return;
    }

    const existing = await prisma.complianceCheck.findMany({
      where: { engagementId, framework },
      select: { controlId: true },
    });
    const existingIds = new Set(existing.map((c) => c.controlId));
    const toCreate = library.filter((c) => !existingIds.has(c.controlId));

    if (toCreate.length > 0) {
      await prisma.complianceCheck.createMany({
        data: toCreate.map((c) => ({
          engagementId,
          framework,
          controlId: c.controlId,
          controlName: c.controlName,
          status: "PENDING" as const,
        })),
      });
    }

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "complianceCheck.seed",
      resourceId: null,
      engagementId,
      result: "SUCCESS",
    });

    res.status(201).json({ created: toCreate.length, alreadyPresent: existingIds.size });
  }
);

const updateSchema = z.object({
  status: z.nativeEnum(ComplianceStatus).optional(),
  notes: z.string().max(10_000).optional(),
});

complianceRouter.patch(
  "/compliance-checks/:id",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = updateSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const check = await prisma.complianceCheck.findUnique({
      where: { id: req.params.id },
      include: { engagement: { select: { clientId: true } } },
    });
    if (!check || !assertOwnOrg(req, check.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const updated = await prisma.complianceCheck.update({
      where: { id: check.id },
      data: {
        status: parsed.data.status,
        notesEnc: parsed.data.notes ? ((await encryptField(kms, parsed.data.notes, `compliance:notes`)) as any) : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "complianceCheck",
      resourceId: updated.id,
      engagementId: check.engagementId,
      result: "SUCCESS",
    });

    res.json({ id: updated.id, status: updated.status });
  }
);

complianceRouter.get("/engagements/:engagementId/compliance-checks", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const checks = await prisma.complianceCheck.findMany({
    where: { engagementId },
    select: { id: true, framework: true, controlId: true, controlName: true, status: true, createdAt: true },
    orderBy: { createdAt: "desc" },
  });

  res.json(checks);
});

complianceRouter.get("/engagements/:engagementId/compliance-summary", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const checks = await prisma.complianceCheck.findMany({ where: { engagementId } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "complianceCheck",
    resourceId: null,
    engagementId,
    result: "SUCCESS",
  });

  const summary = checks.reduce<Record<string, Record<string, number>>>((acc, check) => {
    acc[check.framework] ??= { PENDING: 0, PASS: 0, FAIL: 0, PARTIAL: 0, NOT_APPLICABLE: 0 };
    acc[check.framework][check.status] += 1;
    return acc;
  }, {});

  res.json({ totalControls: checks.length, byFramework: summary });
});

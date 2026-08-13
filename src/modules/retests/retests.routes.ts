import { Router } from "express";
import { z } from "zod";
import { RetestResult } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";

export const retestsRouter = Router({ mergeParams: true });

const createSchema = z.object({
  result: z.nativeEnum(RetestResult),
  notes: z.string().max(10_000).optional(),
});

const resultToFindingStatus: Record<RetestResult, "RETESTED_PASS" | "RETESTED_FAIL" | "REMEDIATING"> = {
  FIXED: "RETESTED_PASS",
  NOT_FIXED: "RETESTED_FAIL",
  PARTIALLY_FIXED: "REMEDIATING",
};

retestsRouter.post("/findings/:findingId/retest", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { findingId } = req.params;
  const { result, notes } = parsed.data;

  let scopedKms = kms;
  if (notes) {
    const finding = await prisma.finding.findUnique({
      where: { id: findingId },
      include: { test: { include: { engagement: { select: { clientId: true } } } } },
    });
    if (!finding) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    scopedKms = await tenantKms(finding.test.engagement.clientId);
  }

  const [retest] = await prisma.$transaction([
    prisma.retest.create({
      data: {
        findingId,
        retestedBy: req.user!.id,
        result,
        notesEnc: notes ? ((await encryptField(scopedKms, notes, `retest:notes`)) as any) : undefined,
      },
    }),
    prisma.finding.update({
      where: { id: findingId },
      data: { status: resultToFindingStatus[result] },
    }),
  ]);

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "CREATE",
    resourceType: "retest",
    resourceId: retest.id,
    result: "SUCCESS",
  });

  res.status(201).json(retest);
});

retestsRouter.get("/findings/:findingId/retest-history", requireAuth, async (req, res) => {
  const finding = await prisma.finding.findUnique({
    where: { id: req.params.findingId },
    include: { test: { include: { engagement: { select: { clientId: true } } } } },
  });
  if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const retests = await prisma.retest.findMany({
    where: { findingId: req.params.findingId },
    orderBy: { retestedAt: "desc" },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "retest",
    resourceId: null,
    result: "SUCCESS",
  });

  res.json(retests.map(({ notesEnc, ...rest }) => rest)); // notes withheld from list view by default
});

import { Router } from "express";
import { z } from "zod";
import { ReportType } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms, objectStorage } from "../../crypto";
import { encryptBuffer, decryptBuffer } from "../../crypto/envelope";
import { newStorageKey } from "../../crypto/storage";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { buildReportContent } from "./report.builder";
import { sideEffectLimiter } from "../../middleware/rate-limit";

export const reportsRouter = Router({ mergeParams: true });

const generateSchema = z.object({ type: z.nativeEnum(ReportType) });

reportsRouter.post(
  "/engagements/:engagementId/reports/generate",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  sideEffectLimiter,
  async (req, res) => {
    const parsed = generateSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId } = req.params;
    const { type } = parsed.data;

    const content = await buildReportContent(prisma, engagementId, type);
    const encrypted = await encryptBuffer(kms, content, `report:${engagementId}:${type}`);
    const storageKey = newStorageKey(`reports/${engagementId}`);
    await objectStorage.put(storageKey, encrypted.ciphertext);

    const priorCount = await prisma.report.count({ where: { engagementId, type } });

    const report = await prisma.report.create({
      data: {
        engagementId,
        type,
        version: priorCount + 1,
        storageKey,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        encryptedDataKey: encrypted.encryptedDataKey,
        kmsKeyId: encrypted.kmsKeyId,
        keyVersion: encrypted.keyVersion,
        generatedBy: req.user!.id,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "report",
      resourceId: report.id,
      engagementId,
      result: "SUCCESS",
    });

    res.status(201).json({ id: report.id, type: report.type, version: report.version });
  }
);

// exec_client only ever sees EXECUTIVE reports listed — matches the download gate below.
reportsRouter.get("/engagements/:engagementId/reports", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const reports = await prisma.report.findMany({
    where: {
      engagementId,
      type: req.user!.role === "EXEC_CLIENT" ? "EXECUTIVE" : undefined,
    },
    select: { id: true, type: true, version: true, generatedAt: true },
    orderBy: { generatedAt: "desc" },
  });

  res.json(reports);
});

// Role-gated: exec_client may only fetch EXECUTIVE reports; technical_client
// and security_admin can fetch any type for engagements they're allowed to see.
reportsRouter.get("/reports/:id/download", requireAuth, async (req, res) => {
  const report = await prisma.report.findUnique({
    where: { id: req.params.id },
    include: { engagement: { select: { clientId: true } } },
  });
  if (!report || !assertOwnOrg(req, report.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  if (req.user!.role === "EXEC_CLIENT" && report.type !== "EXECUTIVE") {
    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "DOWNLOAD",
      resourceType: "report",
      resourceId: report.id,
      engagementId: report.engagementId,
      result: "DENIED",
    });
    res.status(403).json({ error: "Executive role may only download the executive report" });
    return;
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DOWNLOAD",
    resourceType: "report",
    resourceId: report.id,
    engagementId: report.engagementId,
    result: "SUCCESS",
  });

  const ciphertext = await objectStorage.get(report.storageKey);
  const plaintext = await decryptBuffer(
    kms,
    {
      ciphertext,
      iv: report.iv,
      authTag: report.authTag,
      encryptedDataKey: report.encryptedDataKey,
      kmsKeyId: report.kmsKeyId,
    },
    `report:${report.engagementId}:${report.type}`
  );

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename="${report.type.toLowerCase()}-v${report.version}.pdf"`);
  res.send(plaintext);
});

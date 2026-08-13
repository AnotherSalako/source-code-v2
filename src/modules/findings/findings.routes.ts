import { Router } from "express";
import { z } from "zod";
import { Severity } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { importScanItems } from "./import.service";
import { threatResponse } from "../../threat-response";
import { notifyIfSevere } from "../../notifications";

export const findingsRouter = Router({ mergeParams: true });

const createSchema = z.object({
  assetId: z.string().uuid(),
  title: z.string().trim().min(1).max(300),
  description: z.string().min(1).max(20_000),
  severity: z.nativeEnum(Severity),
  cvssScore: z.number().min(0).max(10).optional(),
  reproductionSteps: z.string().max(20_000).optional(),
  remediationGuidance: z.string().max(20_000).optional(),
});

findingsRouter.post(
  "/engagements/:engagementId/tests/:testId/findings",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = createSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { testId } = req.params;
    const f = parsed.data;

    const finding = await prisma.finding.create({
      data: {
        testId,
        assetId: f.assetId,
        title: f.title,
        severity: f.severity,
        cvssScore: f.cvssScore,
        descriptionEnc: (await encryptField(kms, f.description, `finding:description`)) as any,
        reproductionStepsEnc: f.reproductionSteps
          ? ((await encryptField(kms, f.reproductionSteps, `finding:reproductionSteps`)) as any)
          : undefined,
        remediationGuidanceEnc: f.remediationGuidance
          ? ((await encryptField(kms, f.remediationGuidance, `finding:remediationGuidance`)) as any)
          : undefined,
      },
    });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "finding",
      resourceId: finding.id,
      engagementId: req.params.engagementId,
      result: "SUCCESS",
    });

    void notifyIfSevere({
      findingId: finding.id,
      title: finding.title,
      severity: finding.severity,
      engagementId: req.params.engagementId,
    });

    res.status(201).json({ id: finding.id, title: finding.title, severity: finding.severity });
  }
);

const importSchema = z.object({
  format: z.enum(["normalized", "nuclei"]).default("normalized"),
  items: z.array(z.record(z.any())).min(1).max(500),
});

// Bulk-creates findings from automated scanner output rather than one at a
// time by hand. "nuclei" understands Nuclei's JSONL result shape (see
// scan-import.ts); "normalized" expects our own documented item schema
// directly, for any other tool's output converted upstream. Assets are
// matched by decrypting each engagement asset's identifier and comparing
// against the scan result's target — identifiers are encrypted at rest, so
// this can't be done as a SQL WHERE clause.
findingsRouter.post(
  "/engagements/:engagementId/tests/:testId/findings/import",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const parsed = importSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }
    const { engagementId, testId } = req.params;
    const { format, items } = parsed.data;

    const { createdIds, skipped } = await importScanItems({ engagementId, testId, format, items });

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "CREATE",
      resourceType: "finding.import",
      resourceId: null,
      engagementId,
      result: "SUCCESS",
    });

    res.status(201).json({ createdCount: createdIds.length, createdIds, skipped });
  }
);

// List view is deliberately undecrypted (title/severity/status/CVSS only) —
// no *Enc field is ever touched here, so browsing a list never triggers a
// decrypt or an audit "VIEW" of the sensitive fields. Full detail — and the
// decrypt + audit log that comes with it — only happens on GET /findings/:id.
findingsRouter.get("/engagements/:engagementId/findings", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const { testId } = req.query;

  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const findings = await prisma.finding.findMany({
    where: {
      test: { engagementId, id: typeof testId === "string" ? testId : undefined },
    },
    select: {
      id: true,
      testId: true,
      assetId: true,
      title: true,
      severity: true,
      cvssScore: true,
      status: true,
      remediationEffort: true,
      discoveredAt: true,
    },
    orderBy: [{ severity: "desc" }, { discoveredAt: "desc" }],
  });

  res.json(findings);
});

// Remediation roadmap: still-open findings (OPEN/REMEDIATING — fixed,
// accepted-risk, and failed-retest findings aren't "on the roadmap" anymore),
// bucketed by severity x effort so quick wins surface separately from
// longer-term projects. Bucketing logic lives here, once, rather than being
// re-derived in the frontend.
findingsRouter.get("/engagements/:engagementId/roadmap", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({
    where: { id: engagementId },
    select: { clientId: true },
  });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const findings = await prisma.finding.findMany({
    where: { test: { engagementId }, status: { in: ["OPEN", "REMEDIATING"] } },
    select: {
      id: true,
      title: true,
      severity: true,
      status: true,
      remediationEffort: true,
      assetId: true,
      discoveredAt: true,
    },
    orderBy: [{ severity: "desc" }, { discoveredAt: "asc" }],
  });

  const highValue = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
  const lowEffort = new Set(["QUICK_WIN", "SMALL"]);

  const bucketed = findings.map((f) => {
    let bucket: "quick_win" | "long_term" | "plan" | "uncategorized";
    if (!f.remediationEffort) bucket = "uncategorized";
    else if (f.remediationEffort === "LARGE") bucket = "long_term";
    else if (lowEffort.has(f.remediationEffort) && highValue.has(f.severity)) bucket = "quick_win";
    else bucket = "plan";
    return { ...f, bucket };
  });

  res.json(bucketed);
});

// Role-gated read: exec_client gets severity/status/title only (business risk
// view); technical_client and security_admin get the full decrypted finding.
findingsRouter.get("/findings/:id", requireAuth, async (req, res) => {
  const finding = await prisma.finding.findUnique({
    where: { id: req.params.id },
    include: { test: { include: { engagement: { select: { clientId: true } } } } },
  });
  if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "finding",
    resourceId: finding.id,
    result: "SUCCESS",
  });

  const base = {
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    cvssScore: finding.cvssScore,
    status: finding.status,
  };

  if (req.user!.role === "EXEC_CLIENT") {
    res.json(base);
    return;
  }

  const description = await decryptField(kms, finding.descriptionEnc as any, `finding:description`);
  const reproductionSteps = finding.reproductionStepsEnc
    ? await decryptField(kms, finding.reproductionStepsEnc as any, `finding:reproductionSteps`)
    : undefined;
  const remediationGuidance = finding.remediationGuidanceEnc
    ? await decryptField(kms, finding.remediationGuidanceEnc as any, `finding:remediationGuidance`)
    : undefined;

  res.json({ ...base, description, reproductionSteps, remediationGuidance });
});

const patchSchema = z.object({
  status: z.enum(["OPEN", "REMEDIATING", "RETESTED_PASS", "RETESTED_FAIL", "ACCEPTED_RISK"]).optional(),
  remediationEffort: z.enum(["QUICK_WIN", "SMALL", "MEDIUM", "LARGE"]).optional(),
});

findingsRouter.patch("/findings/:id", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const updated = await prisma.finding.update({
    where: { id: req.params.id },
    data: { status: parsed.data.status, remediationEffort: parsed.data.remediationEffort },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "UPDATE",
    resourceType: "finding",
    resourceId: updated.id,
    result: "SUCCESS",
  });

  res.json(updated);
});

// Active response — always human-triggered by clicking this, never called
// automatically by anything in this app. Resolves the finding's own asset
// identifier as the containment target rather than taking one from the
// request body, so this can't be used to ask the configured EDR provider to
// contain an arbitrary, unrelated host.
findingsRouter.post(
  "/findings/:id/response-actions/contain",
  requireAuth,
  requireRole("SECURITY_ADMIN"),
  async (req, res) => {
    const finding = await prisma.finding.findUnique({
      where: { id: req.params.id },
      include: { asset: true, test: { include: { engagement: { select: { clientId: true } } } } },
    });
    if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
      res.status(404).json({ error: "Not found" });
      return;
    }

    const hostIdentifier = await decryptField(kms, finding.asset.identifierEnc as any, `asset:identifier`);
    const result = await threatResponse.containHost(hostIdentifier);

    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "UPDATE",
      resourceType: "finding.responseAction.contain",
      resourceId: finding.id,
      result: result.success ? "SUCCESS" : "DENIED",
    });

    res.json(result);
  }
);

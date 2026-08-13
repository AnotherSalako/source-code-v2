import { Router } from "express";
import { z } from "zod";
import { Severity } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { importScanItems } from "./import.service";
import { threatResponse } from "../../threat-response";
import { notifyIfSevere } from "../../notifications";
import { triageFinding } from "./triage.service";
import { aiTriage } from "../../ai";
import { clusterFindings, computeExploitabilityScore, RankedFinding } from "./clustering";

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
    const { engagementId, testId } = req.params;
    const f = parsed.data;

    const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, select: { clientId: true } });
    if (!engagement) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    const scopedKms = await tenantKms(engagement.clientId);

    const finding = await prisma.finding.create({
      data: {
        testId,
        assetId: f.assetId,
        title: f.title,
        severity: f.severity,
        cvssScore: f.cvssScore,
        descriptionEnc: (await encryptField(scopedKms, f.description, `finding:description`)) as any,
        reproductionStepsEnc: f.reproductionSteps
          ? ((await encryptField(scopedKms, f.reproductionSteps, `finding:reproductionSteps`)) as any)
          : undefined,
        remediationGuidanceEnc: f.remediationGuidance
          ? ((await encryptField(scopedKms, f.remediationGuidance, `finding:remediationGuidance`)) as any)
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
    void triageFinding(finding.id, engagement.clientId, { title: f.title, description: f.description, severity: f.severity });

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

// Structural (non-AI) near-duplicate clustering + exploitability ranking —
// distinct from the per-finding AI triage above: this is deterministic and
// free (src/modules/findings/clustering.ts), so it's safe to compute on
// every request rather than something a human has to explicitly trigger.
// Scoped to findings still worth acting on (OPEN/REMEDIATING/RETESTED_FAIL)
// — the same "still needs attention" set the roadmap above uses, plus
// RETESTED_FAIL since a failed fix attempt is still live risk.
findingsRouter.get("/engagements/:engagementId/findings/clusters", requireAuth, async (req, res) => {
  const { engagementId } = req.params;
  const engagement = await prisma.engagement.findUnique({ where: { id: engagementId }, select: { clientId: true } });
  if (!engagement || !assertOwnOrg(req, engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const findings = await prisma.finding.findMany({
    where: { test: { engagementId }, status: { in: ["OPEN", "REMEDIATING", "RETESTED_FAIL"] } },
    select: {
      id: true,
      title: true,
      severity: true,
      cvssScore: true,
      status: true,
      assetId: true,
      discoveredAt: true,
      asset: { select: { type: true, inScope: true } },
    },
  });

  const ranked: RankedFinding[] = findings.map((f) => ({
    id: f.id,
    title: f.title,
    severity: f.severity,
    cvssScore: f.cvssScore,
    status: f.status,
    assetId: f.assetId,
    discoveredAt: f.discoveredAt,
    exploitability: computeExploitabilityScore(f, f.asset),
  }));
  ranked.sort((a, b) => b.exploitability.score - a.exploitability.score);

  res.json({ findings: ranked, clusters: clusterFindings(ranked) });
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
  // AI-drafted fields — same visibility tier as remediationGuidance, kept
  // clearly separate in the response so a client can never render a draft
  // as if it were reviewed guidance.
  const aiRemediationDraft = finding.aiRemediationDraftEnc
    ? await decryptField(kms, finding.aiRemediationDraftEnc as any, `finding:aiRemediationDraft`)
    : undefined;
  const aiTriageRationale = finding.aiTriageRationaleEnc
    ? await decryptField(kms, finding.aiTriageRationaleEnc as any, `finding:aiTriageRationale`)
    : undefined;

  res.json({
    ...base,
    description,
    reproductionSteps,
    remediationGuidance,
    aiRemediationDraft,
    aiFalsePositiveLikelihood: finding.aiFalsePositiveLikelihood,
    aiTriageRationale,
    aiTriagedAt: finding.aiTriagedAt,
  });
});

const patchSchema = z.object({
  status: z.enum(["OPEN", "REMEDIATING", "RETESTED_PASS", "RETESTED_FAIL", "ACCEPTED_RISK"]).optional(),
  remediationEffort: z.enum(["QUICK_WIN", "SMALL", "MEDIUM", "LARGE"]).optional(),
  // The one-click "promote a draft" action: copies the current
  // aiRemediationDraftEnc into the real, human-owned remediationGuidanceEnc.
  // Still an explicit human PATCH, not something the draft step does on its
  // own — accepting is a decision, not a default.
  acceptAiRemediationDraft: z.boolean().optional(),
});

findingsRouter.patch("/findings/:id", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  let remediationGuidanceEnc: any;
  if (parsed.data.acceptAiRemediationDraft) {
    const existing = await prisma.finding.findUnique({
      where: { id: req.params.id },
      include: { test: { include: { engagement: { select: { clientId: true } } } } },
    });
    if (!existing?.aiRemediationDraftEnc) {
      res.status(400).json({ error: "No AI remediation draft exists for this finding yet — run POST .../findings/:id/triage first" });
      return;
    }
    const draftText = await decryptField(kms, existing.aiRemediationDraftEnc as any, `finding:aiRemediationDraft`);
    const scopedKms = await tenantKms(existing.test.engagement.clientId);
    remediationGuidanceEnc = (await encryptField(scopedKms, draftText, `finding:remediationGuidance`)) as any;
  }

  const updated = await prisma.finding.update({
    where: { id: req.params.id },
    data: { status: parsed.data.status, remediationEffort: parsed.data.remediationEffort, remediationGuidanceEnc },
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

// On-demand (re-)triage — for findings created before this feature existed,
// or to redraft after a description edit. Unlike the fire-and-forget draft
// on creation, this awaits the provider so the caller gets the draft (or a
// clear "nothing drafted") in the same response.
findingsRouter.post("/findings/:id/triage", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const finding = await prisma.finding.findUnique({
    where: { id: req.params.id },
    include: { test: { include: { engagement: { select: { clientId: true } } } } },
  });
  if (!finding || !assertOwnOrg(req, finding.test.engagement.clientId)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const description = await decryptField(kms, finding.descriptionEnc as any, `finding:description`);
  const draft = await aiTriage.draftTriage({ title: finding.title, description, severity: finding.severity });

  if (!draft) {
    res.json({ drafted: false, message: "No AI triage provider configured (AI_TRIAGE_PROVIDER unset), or the request failed." });
    return;
  }

  const scopedKms = await tenantKms(finding.test.engagement.clientId);
  await prisma.finding.update({
    where: { id: finding.id },
    data: {
      aiRemediationDraftEnc: (await encryptField(scopedKms, draft.remediationGuidance, `finding:aiRemediationDraft`)) as any,
      aiFalsePositiveLikelihood: draft.falsePositiveLikelihood,
      aiTriageRationaleEnc: (await encryptField(scopedKms, draft.rationale, `finding:aiTriageRationale`)) as any,
      aiTriagedAt: new Date(),
    },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "UPDATE",
    resourceType: "finding.aiTriage",
    resourceId: finding.id,
    result: "SUCCESS",
  });

  res.json({ drafted: true, ...draft });
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

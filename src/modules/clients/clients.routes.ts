import { Router } from "express";
import { z } from "zod";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { encryptField, decryptField } from "../../crypto/envelope";
import { requireAuth } from "../../middleware/auth";
import { requireRole, assertOwnOrg } from "../../middleware/rbac";
import { sideEffectLimiter } from "../../middleware/rate-limit";
import { writeAuditLog } from "../audit/audit.service";
import { deleteClientData } from "./client-deletion.service";

export const clientsRouter = Router();

const createSchema = z.object({
  name: z.string().trim().min(1).max(200),
  industry: z.string().trim().max(200).optional(),
  primaryContact: z.string().max(2_000).optional(),
  billingInfo: z.string().max(2_000).optional(),
});

// Only internal staff create client records — client users are provisioned
// against an existing client after the contract/authorization is signed.
clientsRouter.post("/", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { name, industry, primaryContact, billingInfo } = parsed.data;

  const client = await prisma.client.create({
    data: {
      name,
      industry,
      primaryContactEnc: primaryContact
        ? ((await encryptField(kms, primaryContact, `client:primaryContact`)) as any)
        : undefined,
      billingInfoEnc: billingInfo
        ? ((await encryptField(kms, billingInfo, `client:billingInfo`)) as any)
        : undefined,
    },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "CREATE",
    resourceType: "client",
    resourceId: client.id,
    result: "SUCCESS",
  });

  res.status(201).json({ id: client.id, name: client.name, industry: client.industry });
});

// Admin sees every client; client-side users see only their own org (so a
// technical/exec user hitting this by habit gets their own record, not a directory).
clientsRouter.get("/", requireAuth, async (req, res) => {
  const clients = await prisma.client.findMany({
    where: req.user!.role === "SECURITY_ADMIN" ? undefined : { id: req.user!.orgId ?? "" },
    orderBy: { createdAt: "desc" },
    select: { id: true, name: true, industry: true, createdAt: true },
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "client",
    resourceId: null,
    result: "SUCCESS",
  });

  res.json(clients);
});

clientsRouter.get("/:id", requireAuth, async (req, res) => {
  const client = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!client || !assertOwnOrg(req, client.id)) {
    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "VIEW",
      resourceType: "client",
      resourceId: req.params.id,
      result: "DENIED",
    });
    res.status(404).json({ error: "Not found" });
    return;
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "client",
    resourceId: client.id,
    result: "SUCCESS",
  });

  // Contact/billing details are only decrypted for internal staff, not client
  // users viewing their own org record — they already know their own contact info.
  const primaryContact =
    req.user!.role === "SECURITY_ADMIN" && client.primaryContactEnc
      ? await decryptField(kms, client.primaryContactEnc as any, `client:primaryContact`)
      : undefined;

  res.json({ id: client.id, name: client.name, industry: client.industry, primaryContact });
});

// Aggregates across every engagement for this client — what makes a retainer
// worth more than a series of one-off reports: whether risk is trending up
// or down, and whether the same issue keeps coming back unfixed between
// engagements. Metadata-only (title/severity/status/assetId), same as the
// per-engagement findings list — no *Enc field touched, so no decrypt and
// no gating needed beyond the usual org-scope check.
clientsRouter.get("/:id/findings-history", requireAuth, async (req, res) => {
  const client = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!client || !assertOwnOrg(req, client.id)) {
    res.status(404).json({ error: "Not found" });
    return;
  }

  const engagements = await prisma.engagement.findMany({
    where: { clientId: client.id },
    orderBy: { createdAt: "asc" },
    select: { id: true, createdAt: true, status: true },
  });
  const engagementIds = engagements.map((e) => e.id);

  const findings = await prisma.finding.findMany({
    where: { test: { engagementId: { in: engagementIds } } },
    select: {
      title: true,
      severity: true,
      status: true,
      assetId: true,
      test: { select: { engagementId: true } },
    },
  });

  const bySeverity: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byStatus[f.status] = (byStatus[f.status] ?? 0) + 1;
  }

  // "Recurring" = the same asset+title showing up in more than one
  // engagement — a finding that keeps coming back unfixed between
  // assessments, not just one that's still open within a single engagement.
  const byKey = new Map<string, { title: string; assetId: string; engagementIds: Set<string> }>();
  for (const f of findings) {
    const key = `${f.assetId}::${f.title}`;
    if (!byKey.has(key)) byKey.set(key, { title: f.title, assetId: f.assetId, engagementIds: new Set() });
    byKey.get(key)!.engagementIds.add(f.test.engagementId);
  }
  const recurring = [...byKey.values()]
    .filter((v) => v.engagementIds.size > 1)
    .map((v) => ({ title: v.title, assetId: v.assetId, occurrences: v.engagementIds.size }))
    .sort((a, b) => b.occurrences - a.occurrences);

  const byEngagement = engagements.map((e) => {
    const counts: Record<string, number> = {};
    let total = 0;
    for (const f of findings) {
      if (f.test.engagementId !== e.id) continue;
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
      total++;
    }
    return { engagementId: e.id, engagementCreatedAt: e.createdAt, status: e.status, counts, total };
  });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "VIEW",
    resourceType: "client.findingsHistory",
    resourceId: client.id,
    result: "SUCCESS",
  });

  res.json({ totalFindings: findings.length, bySeverity, byStatus, recurring, byEngagement });
});

const deleteSchema = z.object({
  // Type-to-confirm against the client's own current name — the same pattern
  // GitHub/Vercel use for "delete this repo/project" — so a stray click or a
  // guessed endpoint can't wipe a client's entire engagement history.
  confirmName: z.string(),
});

// Self-service data erasure — the "right to be forgotten" path referenced in
// the DPA. EXEC_CLIENT (the account-owner-tier role for a client org, see
// README's role table) can erase their OWN org's data without needing to ask
// staff; SECURITY_ADMIN can do it on any org's behalf as a support-assisted
// fallback. TECHNICAL_CLIENT is intentionally excluded — same reasoning as
// their exclusion from raw evidence/technical reports elsewhere: this is an
// account-level decision, not a working-technical-contact one.
//
// This is irreversible: every engagement, asset, test, finding, evidence
// file, report, compliance check, and training session under this client is
// permanently deleted (see client-deletion.service.ts). AuditLog entries are
// preserved, same precedent as the single-User delete route.
clientsRouter.delete("/:id", requireAuth, sideEffectLimiter, async (req, res) => {
  const client = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!client || !assertOwnOrg(req, client.id)) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  if (req.user!.role === "TECHNICAL_CLIENT") {
    await writeAuditLog(prisma, {
      userId: req.user!.id,
      action: "DELETE",
      resourceType: "client.erasure",
      resourceId: client.id,
      result: "DENIED",
    });
    res.status(403).json({ error: "Only an account executive or Enforcer staff can request account data deletion" });
    return;
  }

  const parsed = deleteSchema.safeParse(req.body);
  if (!parsed.success || parsed.data.confirmName !== client.name) {
    res.status(400).json({ error: `Confirmation failed — send { "confirmName": "${client.name}" } to proceed. This permanently deletes all data for this client and cannot be undone.` });
    return;
  }

  const result = await deleteClientData(prisma, client.id, req.user!.id);
  res.json(result);
});

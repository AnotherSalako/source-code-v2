import { Router } from "express";
import { z } from "zod";
import { Role } from "@prisma/client";
import { clerkClient } from "@clerk/express";
import { prisma } from "../../db/prisma";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";
import { writeAuditLog } from "../audit/audit.service";
import { sideEffectLimiter } from "../../middleware/rate-limit";

export const usersRouter = Router();

// Team management for internal staff + client accounts. Provisioning is
// deliberately one action, not two systems to keep in sync by hand: this
// Clerk instance has "Restricted" sign-up enabled (allowlist mode — see
// scripts run during setup, or Clerk dashboard -> Restrictions), so a real
// Clerk account existing is not enough to use the app on its own — a
// matching row here is also required (src/middleware/auth.ts). Adding
// someone means both: this row (authorization: role/org) AND a Clerk
// invitation (identity: lets them actually sign in) — this endpoint does
// both together rather than requiring two separate admin actions across
// two dashboards.

usersRouter.get("/users", requireAuth, requireRole("SECURITY_ADMIN"), async (_req, res) => {
  const users = await prisma.user.findMany({
    orderBy: { createdAt: "desc" },
    select: { id: true, name: true, email: true, role: true, orgId: true, lastLoginAt: true, createdAt: true },
  });
  res.json(users);
});

const createSchema = z.object({
  name: z.string().trim().min(1).max(200),
  email: z.string().trim().toLowerCase().email().max(254),
  role: z.nativeEnum(Role),
  orgId: z.string().uuid().optional(), // required in practice for TECHNICAL_CLIENT/EXEC_CLIENT, null for internal staff
});

usersRouter.post("/users", requireAuth, requireRole("SECURITY_ADMIN"), sideEffectLimiter, async (req, res) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }
  const { name, email, role, orgId } = parsed.data;

  if (role !== "SECURITY_ADMIN" && !orgId) {
    res.status(400).json({ error: "orgId is required for TECHNICAL_CLIENT/EXEC_CLIENT — which client org do they belong to?" });
    return;
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    res.status(409).json({ error: `A user with email ${email} already exists (id=${existing.id})` });
    return;
  }

  const user = await prisma.user.create({ data: { name, email, role, orgId: role === "SECURITY_ADMIN" ? null : orgId } });

  // ignoreExisting: true covers both "already has a Clerk account" (common
  // for internal staff who signed up before being provisioned here) and
  // "already has a pending invite" — either way, this just gets them a
  // fresh invite email rather than erroring the whole request over it.
  let invitationSent = false;
  let invitationError: string | undefined;
  try {
    await clerkClient.invitations.createInvitation({ emailAddress: email, notify: true, ignoreExisting: true });
    invitationSent = true;
  } catch (err) {
    invitationError = err instanceof Error ? err.message : "Unknown error sending Clerk invitation";
  }

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "CREATE",
    resourceType: "user",
    resourceId: user.id,
    result: "SUCCESS",
  });

  res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role, orgId: user.orgId, invitationSent, invitationError });
});

// Revokes app access immediately (no User row = requireAuth 403s them on
// their next request, even mid-session) — the Clerk account itself is left
// alone, since deleting identity is a more sensitive, less reversible
// action better left to an explicit dashboard action if truly needed. This
// does mean their past audit log entries lose the "who" attribution
// (AuditLog.userId is an optional FK, nulled on delete) — a deliberate
// tradeoff to avoid a soft-delete/deactivation system that wasn't asked for.
usersRouter.delete("/users/:id", requireAuth, requireRole("SECURITY_ADMIN"), async (req, res) => {
  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target) {
    res.status(404).json({ error: "Not found" });
    return;
  }
  if (target.id === req.user!.id) {
    res.status(400).json({ error: "Can't remove your own access" });
    return;
  }

  await prisma.user.delete({ where: { id: target.id } });

  await writeAuditLog(prisma, {
    userId: req.user!.id,
    action: "DELETE",
    resourceType: "user",
    resourceId: target.id,
    result: "SUCCESS",
  });

  res.status(204).send();
});

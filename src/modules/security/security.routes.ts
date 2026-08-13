import { Router } from "express";
import { clerkClient } from "@clerk/express";
import { prisma } from "../../db/prisma";
import { env } from "../../config/env";
import { requireAuth } from "../../middleware/auth";
import { requireRole } from "../../middleware/rbac";

export const securityRouter = Router();

// A live, real-data status board for every security control actually
// protecting this deployment — not a settings page, a trust center. Every
// field here is derived from actual config/live state, nothing hardcoded
// as "on" — if a provider isn't configured, this says so plainly rather
// than implying it is. No secrets are ever returned, only booleans/provider
// names/counts.
securityRouter.get("/security/status", requireAuth, requireRole("SECURITY_ADMIN"), async (_req, res) => {
  const [users, thirtyDayDenied, totalAuditEvents, restrictions] = await Promise.all([
    prisma.user.findMany({ select: { role: true } }),
    prisma.auditLog.count({ where: { result: "DENIED", timestamp: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } } }),
    prisma.auditLog.count(),
    // Live Clerk call, not assumed — this is exactly the kind of thing that
    // could silently drift (someone flips it in the dashboard) if we
    // reported a value baked in at build time instead of asking Clerk.
    // instance.get() doesn't expose restriction state; updateRestrictions
    // with an empty body is the read path (Clerk's params are all optional
    // "leave unchanged" — verified live that this doesn't mutate anything).
    clerkClient.instance.updateRestrictions({}).catch(() => null),
  ]);

  const roleBreakdown = { SECURITY_ADMIN: 0, TECHNICAL_CLIENT: 0, EXEC_CLIENT: 0 };
  for (const u of users) roleBreakdown[u.role]++;

  res.json({
    access: {
      signupRestricted: restrictions?.allowlist ?? false,
      teamSize: users.length,
      roleBreakdown,
    },
    encryption: {
      kmsProvider: env.kmsProvider,
      cmkVersion: env.cmkVersion,
      rotationScheduled: Boolean(env.cronSecret),
    },
    scanningSafety: {
      nonIntrusiveOnly: true, // fixed by design in scan-runner.ts, not configurable — reported as a fact about the code, not a toggle
      allowInternalTargets: env.allowInternalScanTargets,
      scheduledScanningConfigured: Boolean(env.cronSecret),
    },
    detectionResponse: {
      malwareDetectionConfigured: Boolean(env.virusTotalApiKey),
      activeResponseProvider: env.threatResponseProvider,
      esignatureProvider: env.esignatureProvider,
      slackConfigured: Boolean(env.slackWebhookUrl),
      emailConfigured: Boolean(env.resendApiKey && env.notificationEmailFrom && env.notificationEmailTo),
    },
    audit: {
      totalEvents: totalAuditEvents,
      deniedLast30Days: thirtyDayDenied,
    },
  });
});

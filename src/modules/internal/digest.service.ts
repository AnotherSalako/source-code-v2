import { prisma } from "../../db/prisma";
import { WeeklyDigest } from "../../notifications/provider";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const STALE_AGENT_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Platform-wide (not per-client) — new findings, watch-mode drift, and
 * agent check-in health since `since` (defaults to a rolling 7 days).
 * Deliberately findMany + manual aggregation rather than groupBy/count,
 * matching how the rest of this app computes summaries (e.g.
 * clients.routes.ts's findings-history) — keeps this testable against the
 * same fake-DB harness every other service test already uses.
 */
export async function buildWeeklyDigest(since: Date = new Date(Date.now() - WEEK_MS)): Promise<WeeklyDigest> {
  const newFindings = await prisma.finding.findMany({ where: { discoveredAt: { gte: since } }, select: { severity: true } });
  const bySeverity: Record<string, number> = {};
  for (const f of newFindings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  const driftAlerts = (await prisma.watchAlert.findMany({ where: { createdAt: { gte: since } } })).length;
  const activeEngagements = (await prisma.engagement.findMany({ where: { status: "ACTIVE" } })).length;

  const staleCutoff = new Date(Date.now() - STALE_AGENT_MS);
  const activeDevices = await prisma.device.findMany({ where: { status: "ACTIVE" } });
  const staleDevices = activeDevices.filter((d) => !d.lastCheckInAt || d.lastCheckInAt < staleCutoff);

  const clientIds = [...new Set(staleDevices.map((d) => d.clientId))];
  const clients = clientIds.length > 0 ? await prisma.client.findMany({ where: { id: { in: clientIds } } }) : [];
  const clientNameById = new Map(clients.map((c) => [c.id, c.name]));

  return {
    since,
    totalNewFindings: newFindings.length,
    newFindingsBySeverity: Object.entries(bySeverity).map(([severity, count]) => ({ severity, count })),
    driftAlerts,
    activeEngagements,
    staleAgents: staleDevices.map((d) => ({
      deviceName: d.name,
      clientName: clientNameById.get(d.clientId) ?? "Unknown client",
      lastCheckInAt: d.lastCheckInAt,
    })),
  };
}

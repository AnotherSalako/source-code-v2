import { UsageEventKind } from "@prisma/client";
import { prisma } from "../../db/prisma";

/**
 * Fire-and-forget-shaped but always awaited by callers — cheap enough
 * (one insert) that there's no reason to risk losing an event to an
 * unhandled rejection the way genuinely slow background work might.
 */
export async function recordUsageEvent(clientId: string, kind: UsageEventKind): Promise<void> {
  await prisma.usageEvent.create({ data: { clientId, kind } });
}

export interface UsageSummary {
  scansRun: number;
  discoveryRuns: number;
  agentCheckIns: number;
  aiCalls: number;
}

/**
 * aiCalls reads AiUsageRecord (src/ai/budget.ts) rather than duplicating
 * those events into UsageEvent — one real source of truth for "was an AI
 * call made," shared by both budget enforcement and this summary, rather
 * than two tables that could drift apart.
 */
export async function getUsageSummary(clientId: string, since?: Date): Promise<UsageSummary> {
  const createdAt = since ? { gte: since } : undefined;

  const [scansRun, discoveryRuns, agentCheckIns, aiCalls] = await Promise.all([
    prisma.usageEvent.count({ where: { clientId, kind: "SCAN", createdAt } }),
    prisma.usageEvent.count({ where: { clientId, kind: "DISCOVERY", createdAt } }),
    prisma.usageEvent.count({ where: { clientId, kind: "AGENT_CHECK_IN", createdAt } }),
    prisma.aiUsageRecord.count({ where: { clientId, createdAt } }),
  ]);

  return { scansRun, discoveryRuns, agentCheckIns, aiCalls };
}

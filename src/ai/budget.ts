import { prisma } from "../db/prisma";
import { env } from "../config/env";

const DAY_MS = 24 * 60 * 60 * 1000;
const MONTH_MS = 30 * DAY_MS;

export type AiEndpoint = "triage" | "nlQuery" | "attackPath";

export interface BudgetCheck {
  allowed: boolean;
  reason?: string;
}

/**
 * Checked before every real AI provider call, across all three features
 * (triage, NL query, attack-path narration) — one shared gate rather than
 * three copies of the same logic. DB-backed, not express-rate-limit's
 * in-memory counters: this app runs on Vercel serverless, where in-memory
 * state doesn't survive a cold start between invocations, so an in-memory
 * cap would silently stop actually capping anything the moment the
 * function instance recycled. A hard budget cap has to outlive the
 * process making the call, or it isn't actually a hard cap.
 *
 * No-ops entirely when AI_TRIAGE_PROVIDER isn't "anthropic" — nothing
 * costs money yet, so there's nothing to record or cap. This means the
 * caps are already wired in and tested *before* anyone flips that switch
 * on, not bolted on afterward under pressure from a surprise bill.
 *
 * Records the call as part of the same check (not a separate step) so a
 * caller can't check, get approved, then forget to record — there is no
 * way to pass this gate without the attempt being counted.
 */
export async function checkAndRecordAiUsage(clientId: string, endpoint: AiEndpoint): Promise<BudgetCheck> {
  if (env.aiTriageProvider !== "anthropic") return { allowed: true };

  const now = Date.now();
  const [dailyCount, monthlyCount] = await Promise.all([
    prisma.aiUsageRecord.count({ where: { clientId, createdAt: { gte: new Date(now - DAY_MS) } } }),
    prisma.aiUsageRecord.count({ where: { clientId, createdAt: { gte: new Date(now - MONTH_MS) } } }),
  ]);

  if (dailyCount >= env.aiDailyCallCap) {
    return { allowed: false, reason: `Daily AI call cap (${env.aiDailyCallCap}) reached for this org — resets on a rolling 24-hour basis.` };
  }
  if (monthlyCount >= env.aiMonthlyCallCap) {
    return { allowed: false, reason: `Monthly AI call cap (${env.aiMonthlyCallCap}) reached for this org.` };
  }

  await prisma.aiUsageRecord.create({ data: { clientId, endpoint } });
  return { allowed: true };
}

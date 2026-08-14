import { z } from "zod";
import { prisma } from "../../db/prisma";
import { attackPathAi } from "../../ai";
import { checkAndRecordAiUsage } from "../../ai/budget";
import { computeExploitabilityScore, RankedFinding } from "./clustering";
import { findAttackPathCandidates, AttackPathCandidate } from "./attack-path";

// Same two-layer validation discipline as nl-query.service.ts: the AI
// provider's raw output is untrusted the moment it comes back. An index
// outside the range of candidates actually sent is dropped, never trusted
// — the model narrating pair #7 when only 5 were sent is exactly the kind
// of thing this check exists to catch, the same way an unrecognized field
// in an NL-query filter gets silently dropped rather than passed through.
const narrationSchema = z.object({
  index: z.number().int(),
  narrative: z.string().trim().min(1).max(1000),
  plausibility: z.enum(["LOW", "MEDIUM", "HIGH"]),
});

export interface AttackPathResult extends AttackPathCandidate {
  narrative: string | null;
  plausibility: "LOW" | "MEDIUM" | "HIGH" | null;
}

/**
 * Computed on demand, never persisted — same precedent as
 * GET /findings/clusters, which recomputes structural output on every
 * request rather than caching it. The structural candidates (attack-path.ts)
 * are returned even when no AI provider is configured or narration fails;
 * only `narrative`/`plausibility` end up null, the underlying signal never
 * disappears because a model call had a bad day.
 */
export async function computeAttackPaths(engagementId: string, clientId: string): Promise<AttackPathResult[]> {
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
      asset: { select: { type: true, inScope: true, criticality: true } },
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

  const assetCriticality = new Map(findings.map((f) => [f.assetId, f.asset.criticality]));
  const candidates = findAttackPathCandidates(ranked, assetCriticality);
  if (candidates.length === 0) return [];

  // One real HTTP call narrates the whole batch (see AttackPathProvider's
  // own comment) — one budget check/record per computeAttackPaths call,
  // not one per candidate.
  const budget = await checkAndRecordAiUsage(clientId, "attackPath");
  const raw = budget.allowed
    ? await attackPathAi.narratePaths(
        candidates.map((c, index) => ({
          index,
          entryTitle: c.entryTitle,
          entrySeverity: c.entrySeverity,
          targetTitle: c.targetTitle,
          targetSeverity: c.targetSeverity,
          targetCriticality: c.targetCriticality,
        }))
      )
    : null;

  const narrationByIndex = new Map<number, { narrative: string; plausibility: "LOW" | "MEDIUM" | "HIGH" }>();
  if (raw) {
    for (const item of raw) {
      const parsed = narrationSchema.safeParse(item);
      if (!parsed.success) continue;
      if (parsed.data.index < 0 || parsed.data.index >= candidates.length) continue;
      narrationByIndex.set(parsed.data.index, { narrative: parsed.data.narrative, plausibility: parsed.data.plausibility });
    }
  }

  return candidates.map((c, index) => {
    const narration = narrationByIndex.get(index);
    return { ...c, narrative: narration?.narrative ?? null, plausibility: narration?.plausibility ?? null };
  });
}

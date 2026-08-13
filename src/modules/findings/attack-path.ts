import { Criticality, Severity } from "@prisma/client";
import { RankedFinding } from "./clustering";

// Deliberately NOT a network-reachability graph — Jupiter doesn't model
// which asset can actually reach which other asset (no such data exists
// anywhere in this schema), so pretending to trace a real path would be
// fabricating a signal this app has no basis for. What this actually is:
// structural co-occurrence — "an internet-facing entry point and a
// high-value target both have live findings in the same engagement" is a
// fact worth a human's attention, not proof a path exists. The honesty
// line matters here specifically because "attack path" sounds far more
// authoritative than "these two things are both true at once."

const ENTRY_SEVERITIES = new Set<Severity>([Severity.HIGH, Severity.CRITICAL]);
const TARGET_CRITICALITIES = new Set<Criticality>([Criticality.HIGH, Criticality.CRITICAL]);
const MAX_ENTRY_POINTS = 5;
const MAX_TARGETS = 5;
const MAX_CANDIDATES = 10; // bounds the batch sent to the (optional) AI narration step, not just the structural pass

export interface AttackPathCandidate {
  entryFindingId: string;
  entryAssetId: string;
  entryTitle: string;
  entrySeverity: Severity;
  entryExploitabilityScore: number;
  targetFindingId: string;
  targetAssetId: string;
  targetTitle: string;
  targetSeverity: Severity;
  targetCriticality: Criticality;
}

/**
 * Pairs each candidate entry point (a HIGH/CRITICAL finding on an
 * internet-facing, in-scope asset — reuses computeExploitabilityScore's
 * existing internetFacing signal from clustering.ts, not a second
 * definition of the same idea) with each candidate high-value target (a
 * live finding on a HIGH/CRITICAL-criticality asset), excluding pairs on
 * the same asset — pivoting to yourself isn't a path. Bounded on both
 * sides (top N by exploitability/severity) so this stays O(1)-ish rather
 * than scaling with finding count, and the pair count stays small enough
 * to hand an AI narration step in one batched call.
 */
export function findAttackPathCandidates(
  findings: RankedFinding[],
  assetCriticality: Map<string, Criticality>
): AttackPathCandidate[] {
  const entryPoints = findings
    .filter((f) => f.exploitability.internetFacing && ENTRY_SEVERITIES.has(f.severity))
    .sort((a, b) => b.exploitability.score - a.exploitability.score)
    .slice(0, MAX_ENTRY_POINTS);

  const targets = findings
    .filter((f) => {
      const criticality = assetCriticality.get(f.assetId);
      return criticality && TARGET_CRITICALITIES.has(criticality);
    })
    .sort((a, b) => b.exploitability.score - a.exploitability.score)
    .slice(0, MAX_TARGETS);

  const candidates: AttackPathCandidate[] = [];
  for (const entry of entryPoints) {
    for (const target of targets) {
      if (entry.assetId === target.assetId) continue;
      if (entry.id === target.id) continue;
      candidates.push({
        entryFindingId: entry.id,
        entryAssetId: entry.assetId,
        entryTitle: entry.title,
        entrySeverity: entry.severity,
        entryExploitabilityScore: entry.exploitability.score,
        targetFindingId: target.id,
        targetAssetId: target.assetId,
        targetTitle: target.title,
        targetSeverity: target.severity,
        targetCriticality: assetCriticality.get(target.assetId)!,
      });
      if (candidates.length >= MAX_CANDIDATES) return candidates;
    }
  }
  return candidates;
}

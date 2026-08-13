/**
 * Same swappable-provider shape as AiTriageProvider/NlQueryProvider —
 * narrow and advisory-only. The structural candidate detection
 * (src/modules/findings/attack-path.ts) already decided which entry/target
 * pairs are worth surfacing; this provider's only job is narrating *why*
 * each pair might matter, referenced by the index the caller assigned, not
 * by anything the model invents. It never proposes a new pair, never
 * invents a finding/asset ID — see attack-path.service.ts for why that
 * matters (an out-of-range or malformed index is dropped, not trusted).
 */
export interface PathNarration {
  index: number;
  narrative: string;
  plausibility: "LOW" | "MEDIUM" | "HIGH";
}

export interface AttackPathProvider {
  narratePaths(
    candidates: { index: number; entryTitle: string; entrySeverity: string; targetTitle: string; targetSeverity: string; targetCriticality: string }[]
  ): Promise<PathNarration[] | null>;
}

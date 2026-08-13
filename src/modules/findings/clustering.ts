import { AssetType, FindingStatus, Severity } from "@prisma/client";

// Deliberately dependency-free — no fuzzy-matching library, just a handful
// of short, testable functions. Matches this codebase's existing preference
// for raw implementations over pulling in a package for something this
// small (see src/esignature/providers/documenso.ts using raw fetch instead
// of an SDK). No AI call either: unlike the per-finding remediation
// drafting in triage.service.ts, clustering and exploitability ranking are
// structural — deterministic, free, and instant, which is what makes them
// safe to compute on every page load rather than something a human has to
// explicitly request.

const STOP_WORDS = new Set(["a", "an", "the", "on", "in", "of", "for", "to", "at", "and", "or", "is", "are", "with"]);

/** Strips paths, numbers, and punctuation, then drops stop words — "Missing CSP header on /login" and "Missing CSP header on /admin/users" reduce to the same token set. */
export function normalizeTitleTokens(title: string): Set<string> {
  const stripped = title
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/\/[a-z0-9/_-]*/gi, " ") // paths
    .replace(/[^a-z0-9\s]/g, " ") // punctuation
    .replace(/\b\d+\b/g, " "); // bare numbers (ports, IDs)
  const tokens = stripped.split(/\s+/).filter((t) => t.length > 1 && !STOP_WORDS.has(t));
  return new Set(tokens);
}

/** Jaccard similarity over normalized title tokens — 1.0 identical token sets, 0.0 nothing in common. */
export function titleSimilarity(a: string, b: string): number {
  const tokensA = normalizeTitleTokens(a);
  const tokensB = normalizeTitleTokens(b);
  if (tokensA.size === 0 || tokensB.size === 0) return 0;
  let intersection = 0;
  for (const t of tokensA) if (tokensB.has(t)) intersection++;
  const union = tokensA.size + tokensB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

const SIMILARITY_THRESHOLD = 0.5;

export interface FindingForClustering {
  id: string;
  title: string;
  severity: Severity;
  cvssScore: number | null;
  status: FindingStatus;
  assetId: string;
  discoveredAt: Date;
}

export interface RankedFinding extends FindingForClustering {
  exploitability: ExploitabilityBreakdown;
}

export interface Cluster {
  representativeTitle: string;
  findingIds: string[];
  assetIds: string[];
  memberCount: number;
  assetCount: number;
  maxSeverity: Severity;
  maxExploitabilityScore: number;
}

/**
 * Greedy single-pass clustering: each finding joins the first existing
 * cluster whose representative title is similar enough, else starts a new
 * one. O(n * clusters), not O(n²), for the finding counts one engagement
 * realistically has. Input must already carry exploitabilityScore (see
 * computeExploitabilityScore) — clustering and ranking share one pass over
 * the same finding list rather than being two separate queries.
 */
export function clusterFindings(findings: RankedFinding[]): Cluster[] {
  const clusters: Cluster[] = [];

  for (const finding of findings) {
    const existing = clusters.find((c) => titleSimilarity(c.representativeTitle, finding.title) >= SIMILARITY_THRESHOLD);
    if (existing) {
      existing.findingIds.push(finding.id);
      if (!existing.assetIds.includes(finding.assetId)) existing.assetIds.push(finding.assetId);
      existing.assetCount = existing.assetIds.length;
      existing.memberCount = existing.findingIds.length;
      if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[existing.maxSeverity]) existing.maxSeverity = finding.severity;
      existing.maxExploitabilityScore = Math.max(existing.maxExploitabilityScore, finding.exploitability.score);
    } else {
      clusters.push({
        representativeTitle: finding.title,
        findingIds: [finding.id],
        assetIds: [finding.assetId],
        memberCount: 1,
        assetCount: 1,
        maxSeverity: finding.severity,
        maxExploitabilityScore: finding.exploitability.score,
      });
    }
  }

  return clusters.sort((a, b) => b.maxExploitabilityScore - a.maxExploitabilityScore);
}

const SEVERITY_ORDER: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const SEVERITY_BASE: Record<Severity, number> = { INFO: 5, LOW: 20, MEDIUM: 40, HIGH: 70, CRITICAL: 95 };
// A failed retest means a fix was attempted and didn't hold — still fully
// live risk, arguably more urgent than a freshly-discovered OPEN finding.
// RETESTED_PASS/ACCEPTED_RISK score zero: neither is "still needs fixing."
const STATUS_WEIGHT: Record<FindingStatus, number> = {
  OPEN: 1,
  REMEDIATING: 0.7,
  RETESTED_FAIL: 1,
  RETESTED_PASS: 0,
  ACCEPTED_RISK: 0,
};
const INTERNET_FACING_TYPES = new Set<AssetType>([AssetType.WEB, AssetType.API]);
const MAX_AGE_BONUS_DAYS = 90;
const AGE_BONUS_POINTS = 15;

export interface ExploitabilityBreakdown {
  score: number; // 0-100
  severityComponent: number;
  internetFacing: boolean;
  daysOpen: number;
  ageBonus: number;
  statusWeight: number;
}

/**
 * Deterministic, explainable stand-in for "real exploitability" — no model
 * call, no network, just severity/CVSS blended with signals raw scanner
 * severity doesn't capture on its own: is this actually internet-reachable,
 * how long has it sat open, and is it still live. Every component is
 * returned alongside the score so a reviewer can see why something ranked
 * where it did — same "never a bare number with no justification" rule the
 * AI triage rationale already follows (src/ai/provider.ts).
 */
export function computeExploitabilityScore(
  finding: FindingForClustering,
  asset: { type: AssetType; inScope: boolean },
  now: Date = new Date()
): ExploitabilityBreakdown {
  const severityComponent =
    finding.cvssScore != null ? (SEVERITY_BASE[finding.severity] + finding.cvssScore * 10) / 2 : SEVERITY_BASE[finding.severity];
  const internetFacing = INTERNET_FACING_TYPES.has(asset.type) && asset.inScope;
  const daysOpen = Math.max(0, Math.floor((now.getTime() - finding.discoveredAt.getTime()) / (1000 * 60 * 60 * 24)));
  const ageBonus = Math.min(daysOpen / MAX_AGE_BONUS_DAYS, 1) * AGE_BONUS_POINTS;
  const statusWeight = STATUS_WEIGHT[finding.status];

  const raw = (severityComponent * (internetFacing ? 1.2 : 1) + ageBonus) * statusWeight;
  const score = Math.max(0, Math.min(100, Math.round(raw)));

  return {
    score,
    severityComponent: Math.round(severityComponent),
    internetFacing,
    daysOpen,
    ageBonus: Math.round(ageBonus),
    statusWeight,
  };
}

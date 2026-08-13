import { TestType } from "@prisma/client";
import { titleSimilarity, SIMILARITY_THRESHOLD } from "./clustering";

// Deterministic complement to the AI triage's aiFalsePositiveLikelihood
// (src/ai/providers/anthropic.ts), same relationship exploitability
// scoring above has to AI triage's remediation draft — free, instant,
// explainable, safe to compute on every request. Direction matches the AI
// field's own semantics: HIGHER score/likelihood means MORE likely to be
// a false positive, so the two can be shown side by side without either
// one meaning the opposite of what it looks like.
//
// Every signal here is something this app can already observe without
// guessing at a specific scanner's per-template accuracy (which this app
// has no real data on) — test provenance, whether the finding is even
// independently verifiable, and whether it's corroborated by near-
// duplicates elsewhere. Deliberately asymmetric on that last one: being
// corroborated by similar findings elsewhere is real evidence of a
// systemic issue (lowers the score meaningfully); being a singleton is
// NOT treated as evidence of being a false positive — plenty of real
// findings are genuinely unique, so singleton status only ever leaves the
// baseline where it already was.

const HUMAN_VERIFIED_BASE = 15; // PENTEST/COMPLIANCE_REVIEW — a person already looked at this
const AUTOMATED_BASE = 40; // VULN_SCAN — nobody's confirmed it by hand yet
const NO_REPRODUCTION_STEPS_PENALTY = 20; // can't be independently re-verified from what's recorded
const NO_CVSS_PENALTY = 10; // never went through structured scoring
const STRONG_CORROBORATION_DISCOUNT = 20; // 2+ similar findings elsewhere
const WEAK_CORROBORATION_DISCOUNT = 10; // exactly 1 similar finding elsewhere

export interface FalsePositiveInput {
  id: string;
  title: string;
  cvssScore: number | null;
  hasReproductionSteps: boolean; // caller passes the *presence* of reproductionStepsEnc, never the decrypted content — this never needs to read what the steps actually say
  testType: TestType;
}

export interface FalsePositiveBreakdown {
  score: number; // 0-100
  likelihood: "LOW" | "MEDIUM" | "HIGH";
  humanVerified: boolean;
  hasReproductionSteps: boolean;
  hasCvssScore: boolean;
  corroboratedByCount: number;
}

export function computeFalsePositiveScore(target: FalsePositiveInput, allFindings: FalsePositiveInput[]): FalsePositiveBreakdown {
  const humanVerified = target.testType === TestType.PENTEST || target.testType === TestType.COMPLIANCE_REVIEW;
  let score = humanVerified ? HUMAN_VERIFIED_BASE : AUTOMATED_BASE;

  if (!target.hasReproductionSteps) score += NO_REPRODUCTION_STEPS_PENALTY;
  if (target.cvssScore == null) score += NO_CVSS_PENALTY;

  const corroboratedByCount = allFindings.filter(
    (f) => f.id !== target.id && titleSimilarity(f.title, target.title) >= SIMILARITY_THRESHOLD
  ).length;
  if (corroboratedByCount >= 2) score -= STRONG_CORROBORATION_DISCOUNT;
  else if (corroboratedByCount >= 1) score -= WEAK_CORROBORATION_DISCOUNT;

  score = Math.max(0, Math.min(100, score));
  const likelihood: FalsePositiveBreakdown["likelihood"] = score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";

  return {
    score,
    likelihood,
    humanVerified,
    hasReproductionSteps: target.hasReproductionSteps,
    hasCvssScore: target.cvssScore != null,
    corroboratedByCount,
  };
}

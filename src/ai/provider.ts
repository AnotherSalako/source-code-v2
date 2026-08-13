export type FalsePositiveLikelihood = "LOW" | "MEDIUM" | "HIGH";

export interface TriageDraft {
  remediationGuidance: string;
  falsePositiveLikelihood: FalsePositiveLikelihood;
  rationale: string; // the model's stated reasoning — always shown to the human reviewer, never hidden
}

/**
 * Swappable AI-assistance boundary, same pattern as ThreatResponseProvider
 * (src/threat-response/provider.ts) and ESignatureProvider. Deliberately
 * narrow and advisory-only: this never writes to a Finding's real
 * `status`, `severity`, or `remediationGuidance` fields directly — it only
 * ever produces a *draft* a human explicitly reviews and accepts (or
 * discards). "Speeds up the human-in-the-loop step without removing it,"
 * same philosophy as the active-response containment action.
 */
export interface AiTriageProvider {
  draftTriage(input: { title: string; description: string; severity: string }): Promise<TriageDraft | null>;
}

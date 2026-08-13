import { AiTriageProvider, TriageDraft } from "./provider";
import { NlQueryProvider } from "./query-provider";
import { AttackPathProvider, PathNarration } from "./attack-path-provider";

/**
 * Default provider — drafts nothing, rather than pretending to. This is
 * what's active until AI_TRIAGE_PROVIDER is set to a real one with real
 * credentials; findings simply have no aiRemediationDraft/aiFalsePositiveLikelihood.
 */
export class NoopAiTriageProvider implements AiTriageProvider {
  async draftTriage(): Promise<TriageDraft | null> {
    return null;
  }
}

/** Same "absent rather than fake" default as NoopAiTriageProvider — NL querying is simply unavailable, not silently degraded to something pretending to work. */
export class NoopNlQueryProvider implements NlQueryProvider {
  async translateQuery(): Promise<Record<string, unknown> | null> {
    return null;
  }
}

/** Structural candidates (attack-path.ts) still return without narration when this is active — only the prose explanation is missing, not the underlying signal. */
export class NoopAttackPathProvider implements AttackPathProvider {
  async narratePaths(): Promise<PathNarration[] | null> {
    return null;
  }
}

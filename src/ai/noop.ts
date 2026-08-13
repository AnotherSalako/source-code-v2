import { AiTriageProvider, TriageDraft } from "./provider";

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

import { prisma } from "../../db/prisma";
import { encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { logger } from "../../config/logger";
import { aiTriage } from "../../ai";

/**
 * Fire-and-forget AI triage on finding creation (both the manual and
 * scan-import paths call this) — never blocks the response, never throws.
 * Only ever writes the ai* fields (see schema.prisma); a human always
 * explicitly reviews (GET /findings/:id) and accepts
 * (PATCH .../findings/:id { acceptAiRemediationDraft: true }) before a
 * draft becomes real remediation guidance.
 *
 * `clientId` is the finding's owning client (its engagement's clientId) —
 * callers already have this in scope, so it's passed in rather than
 * re-derived here, and used to encrypt under that client's own key if
 * they've been assigned one (src/crypto/tenant.ts).
 */
export async function triageFinding(
  findingId: string,
  clientId: string,
  input: { title: string; description: string; severity: string }
): Promise<void> {
  try {
    const draft = await aiTriage.draftTriage(input);
    if (!draft) return; // no provider configured, or the request failed — leave the finding undrafted, not an error

    const scopedKms = await tenantKms(clientId);
    await prisma.finding.update({
      where: { id: findingId },
      data: {
        aiRemediationDraftEnc: (await encryptField(scopedKms, draft.remediationGuidance, `finding:aiRemediationDraft`)) as any,
        aiFalsePositiveLikelihood: draft.falsePositiveLikelihood,
        aiTriageRationaleEnc: (await encryptField(scopedKms, draft.rationale, `finding:aiTriageRationale`)) as any,
        aiTriagedAt: new Date(),
      },
    });
  } catch (err) {
    logger.error({ err, findingId }, "AI triage failed — finding left without a draft");
  }
}

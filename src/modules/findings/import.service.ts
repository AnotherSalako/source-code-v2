import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { adaptNucleiResult, normalizedImportItemSchema, NormalizedImportItem } from "./scan-import";
import { notifyIfSevere } from "../../notifications";

export interface ImportOutcome {
  createdIds: string[];
  skipped: { index: number; reason: string }[];
}

/**
 * Shared by both the manual "POST .../findings/import" upload and the
 * in-app scan orchestrator (src/modules/scanning) — same dedup and
 * asset-matching rules either way, so a scheduled/triggered scan can never
 * behave differently from a hand-uploaded report.
 *
 * `forceAssetId`, when given, skips identifier-based asset matching
 * entirely and assigns every item to that asset. The orchestrator already
 * knows which asset it scanned; re-deriving it from Nuclei's bare-host
 * `target` field would be redundant and, worse, can silently fail to match
 * when an asset's identifier is a full URL rather than a bare host (Nuclei
 * reports host only, no scheme) — see README "Website scanning" section.
 */
export async function importScanItems(params: {
  engagementId: string;
  testId: string;
  format: "normalized" | "nuclei";
  items: Record<string, unknown>[];
  forceAssetId?: string;
}): Promise<ImportOutcome> {
  const { engagementId, testId, format, items, forceAssetId } = params;

  let identifierToAssetId: Map<string, string> | null = null;
  if (!forceAssetId) {
    const assets = await prisma.asset.findMany({ where: { engagementId } });
    identifierToAssetId = new Map<string, string>();
    for (const asset of assets) {
      const identifier = await decryptField(kms, asset.identifierEnc as any, `asset:identifier`);
      identifierToAssetId.set(identifier, asset.id);
    }
  }

  // A re-scan of the same target will re-report the same issues every
  // time — without this, running the same scan on a schedule would spam a
  // fresh duplicate finding per cycle instead of leaving the existing open
  // one alone. Scoped to the whole engagement (not just this test), since
  // "is this still open" doesn't care which scan run first found it.
  const existingOpen = await prisma.finding.findMany({
    where: { test: { engagementId }, status: { in: ["OPEN", "REMEDIATING"] } },
    select: { assetId: true, title: true },
  });
  const openKeys = new Set(existingOpen.map((f) => `${f.assetId}::${f.title}`));

  const createdIds: string[] = [];
  const skipped: { index: number; reason: string }[] = [];

  for (const [index, raw] of items.entries()) {
    let normalized: NormalizedImportItem | null;
    if (format === "nuclei") {
      normalized = adaptNucleiResult(raw);
    } else {
      const result = normalizedImportItemSchema.safeParse(raw);
      normalized = result.success ? result.data : null;
    }
    if (!normalized) {
      skipped.push({ index, reason: "Missing or invalid required fields (title, description, severity)" });
      continue;
    }

    const assetId =
      forceAssetId ??
      normalized.assetId ??
      (normalized.assetIdentifier ? identifierToAssetId!.get(normalized.assetIdentifier) : undefined);
    if (!assetId) {
      skipped.push({
        index,
        reason: `Could not match an asset in this engagement for "${normalized.assetIdentifier ?? "(no target given)"}" — add the asset first or supply assetId directly`,
      });
      continue;
    }

    if (openKeys.has(`${assetId}::${normalized.title}`)) {
      skipped.push({ index, reason: `Already an open finding for "${normalized.title}" on this asset — not duplicated` });
      continue;
    }

    const finding = await prisma.finding.create({
      data: {
        testId,
        assetId,
        title: normalized.title,
        severity: normalized.severity,
        cvssScore: normalized.cvssScore,
        descriptionEnc: (await encryptField(kms, normalized.description, `finding:description`)) as any,
        remediationGuidanceEnc: normalized.remediationGuidance
          ? ((await encryptField(kms, normalized.remediationGuidance, `finding:remediationGuidance`)) as any)
          : undefined,
      },
    });
    createdIds.push(finding.id);
    void notifyIfSevere({ findingId: finding.id, title: finding.title, severity: finding.severity, engagementId });
    openKeys.add(`${assetId}::${normalized.title}`); // same import batch reporting the same issue twice
  }

  return { createdIds, skipped };
}

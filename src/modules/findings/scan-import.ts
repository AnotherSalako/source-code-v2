import { z } from "zod";
import { Severity } from "@prisma/client";

export const normalizedImportItemSchema = z.object({
  title: z.string().min(1),
  description: z.string().min(1),
  severity: z.nativeEnum(Severity),
  cvssScore: z.number().min(0).max(10).optional(),
  assetId: z.string().uuid().optional(),
  assetIdentifier: z.string().optional(),
  remediationGuidance: z.string().optional(),
});

export type NormalizedImportItem = z.infer<typeof normalizedImportItemSchema>;

const NUCLEI_SEVERITY: Record<string, Severity> = {
  info: "INFO",
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  critical: "CRITICAL",
};

/**
 * Adapts one line of Nuclei's JSONL scan output (https://nuclei.projectdiscovery.io/)
 * into our normalized finding-import shape. Nuclei is free/open-source and a
 * common choice for authorized automated scanning — this is the integration
 * point for "run a scan, then import the results" rather than embedding a
 * scanner binary in this app (not feasible in a serverless deployment, and
 * arguably the wrong place for it regardless — scanning happens on
 * infrastructure the tester controls, this app manages the findings that
 * come out of it).
 */
export function adaptNucleiResult(raw: unknown): NormalizedImportItem | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const info = r.info as Record<string, unknown> | undefined;
  const templateId = r["template-id"];
  if (!info || typeof templateId !== "string") return null;

  const rawSeverity = String(info.severity ?? "info").toLowerCase();
  const severity = NUCLEI_SEVERITY[rawSeverity] ?? "INFO";
  const target = (r.host as string | undefined) ?? (r["matched-at"] as string | undefined);

  const item = {
    title: typeof info.name === "string" ? info.name : templateId,
    description:
      typeof info.description === "string" && info.description
        ? info.description
        : `Matched by Nuclei template "${templateId}"${target ? ` against ${target}` : ""}.`,
    severity,
    assetIdentifier: target,
  };

  const parsed = normalizedImportItemSchema.safeParse(item);
  return parsed.success ? parsed.data : null;
}

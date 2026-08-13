import { z } from "zod";
import { Prisma } from "@prisma/client";
import { prisma } from "../../db/prisma";
import { nlQuery } from "../../ai";

// The one real security boundary for this whole feature: every field the
// AI provider claims to have extracted gets re-checked here against a
// fixed whitelist before it ever reaches a Prisma query. Unknown keys are
// silently dropped rather than failing the whole interpretation — a model
// hallucinating one extra field shouldn't discard three other valid ones,
// same "don't overreact to one bad field" precedent as AI triage falling
// back to MEDIUM on an unparseable likelihood rather than failing outright.
const dateStringSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "expected YYYY-MM-DD");

const nlFilterSchema = z.object({
  severity: z.array(z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])).max(5).optional(),
  status: z.array(z.enum(["OPEN", "REMEDIATING", "RETESTED_PASS", "RETESTED_FAIL", "ACCEPTED_RISK"])).max(5).optional(),
  assetType: z.array(z.enum(["WEB", "MOBILE", "SERVER", "CLOUD", "NETWORK", "API"])).max(6).optional(),
  cvssMin: z.number().min(0).max(10).optional(),
  cvssMax: z.number().min(0).max(10).optional(),
  discoveredAfter: dateStringSchema.optional(),
  discoveredBefore: dateStringSchema.optional(),
  titleContains: z.string().trim().min(1).max(200).optional(),
});

export type NlFilter = z.infer<typeof nlFilterSchema>;

/** Turns a validated filter into a Prisma where-clause. Every value here came through nlFilterSchema first — nothing from the AI's raw output reaches this function. */
function buildWhereClause(engagementId: string, filter: NlFilter): Prisma.FindingWhereInput {
  const where: Prisma.FindingWhereInput = { test: { engagementId } };

  if (filter.severity?.length) where.severity = { in: filter.severity };
  if (filter.status?.length) where.status = { in: filter.status };
  if (filter.assetType?.length) where.asset = { type: { in: filter.assetType } };
  if (filter.cvssMin !== undefined || filter.cvssMax !== undefined) {
    where.cvssScore = {
      ...(filter.cvssMin !== undefined ? { gte: filter.cvssMin } : {}),
      ...(filter.cvssMax !== undefined ? { lte: filter.cvssMax } : {}),
    };
  }
  if (filter.discoveredAfter || filter.discoveredBefore) {
    where.discoveredAt = {
      ...(filter.discoveredAfter ? { gte: new Date(filter.discoveredAfter) } : {}),
      ...(filter.discoveredBefore ? { lte: new Date(`${filter.discoveredBefore}T23:59:59.999Z`) } : {}),
    };
  }
  // Prisma's `contains` is parameterized like every other Prisma call in
  // this app — this is not string-concatenated into a query anywhere, the
  // same as every *Enc field's plaintext equivalent is handled elsewhere.
  if (filter.titleContains) where.title = { contains: filter.titleContains, mode: "insensitive" };

  return where;
}

export interface NlQueryResult {
  understood: boolean;
  interpretedFilter: NlFilter | null;
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    cvssScore: number | null;
    status: string;
    assetId: string;
    discoveredAt: Date;
  }>;
}

/**
 * Translates a natural-language question into findings, scoped to one
 * engagement (the route enforces org ownership before this ever runs).
 * `understood: false` covers every failure mode uniformly — no provider
 * configured, the provider errored, or it returned something that didn't
 * survive validation — because a caller shouldn't need to tell those apart
 * to know "try rephrasing the question" is the right next step either way.
 */
export async function resolveNlQuery(engagementId: string, question: string): Promise<NlQueryResult> {
  const raw = await nlQuery.translateQuery(question);
  if (!raw) return { understood: false, interpretedFilter: null, findings: [] };

  const parsed = nlFilterSchema.safeParse(raw);
  if (!parsed.success) return { understood: false, interpretedFilter: null, findings: [] };

  const where = buildWhereClause(engagementId, parsed.data);
  const findings = await prisma.finding.findMany({
    where,
    select: { id: true, title: true, severity: true, cvssScore: true, status: true, assetId: true, discoveredAt: true },
    orderBy: [{ severity: "desc" }, { discoveredAt: "desc" }],
    take: 200, // same spirit as MAX_CANDIDATES elsewhere — a bounded result set, not "return literally everything that ever matched"
  });

  return { understood: true, interpretedFilter: parsed.data, findings };
}

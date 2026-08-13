import { describe, expect, it } from "vitest";
import { computeExploitabilityScore, RankedFinding } from "../src/modules/findings/clustering";
import { findAttackPathCandidates } from "../src/modules/findings/attack-path";

function ranked(
  overrides: Partial<{ id: string; title: string; severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; assetId: string; assetType: "WEB" | "MOBILE" | "SERVER" | "CLOUD" | "NETWORK" | "API"; inScope: boolean }>
): RankedFinding {
  const base = {
    id: overrides.id ?? "f1",
    title: overrides.title ?? "A finding",
    severity: overrides.severity ?? "HIGH",
    cvssScore: null,
    status: "OPEN" as const,
    assetId: overrides.assetId ?? "asset-1",
    discoveredAt: new Date(),
  };
  return { ...base, exploitability: computeExploitabilityScore(base, { type: overrides.assetType ?? "WEB", inScope: overrides.inScope ?? true }) };
}

describe("findAttackPathCandidates", () => {
  it("pairs an internet-facing HIGH/CRITICAL entry with a live finding on a high-criticality asset", () => {
    const entry = ranked({ id: "entry-1", title: "SQLi in login form", severity: "CRITICAL", assetId: "web-asset", assetType: "WEB" });
    const target = ranked({ id: "target-1", title: "Weak credentials on domain controller", severity: "MEDIUM", assetId: "dc-asset", assetType: "SERVER" });
    const criticality = new Map([
      ["web-asset", "LOW" as const],
      ["dc-asset", "CRITICAL" as const],
    ]);

    const candidates = findAttackPathCandidates([entry, target], criticality);

    expect(candidates).toHaveLength(1);
    expect(candidates[0].entryFindingId).toBe("entry-1");
    expect(candidates[0].targetFindingId).toBe("target-1");
  });

  it("never pairs a finding with itself or another finding on the same asset", () => {
    const entry = ranked({ id: "entry-1", severity: "CRITICAL", assetId: "web-asset", assetType: "WEB" });
    const alsoOnWebAsset = ranked({ id: "target-1", severity: "HIGH", assetId: "web-asset", assetType: "WEB" });
    const criticality = new Map([["web-asset", "CRITICAL" as const]]);

    const candidates = findAttackPathCandidates([entry, alsoOnWebAsset], criticality);

    expect(candidates).toHaveLength(0);
  });

  it("excludes a MEDIUM/LOW-severity finding from being an entry point even on an internet-facing asset", () => {
    const weakEntry = ranked({ id: "entry-1", severity: "MEDIUM", assetId: "web-asset", assetType: "WEB" });
    const target = ranked({ id: "target-1", severity: "HIGH", assetId: "dc-asset", assetType: "SERVER" });
    const criticality = new Map([
      ["web-asset", "LOW" as const],
      ["dc-asset", "CRITICAL" as const],
    ]);

    expect(findAttackPathCandidates([weakEntry, target], criticality)).toHaveLength(0);
  });

  it("excludes a finding on a LOW/MEDIUM-criticality asset from being a target even if severe", () => {
    const entry = ranked({ id: "entry-1", severity: "CRITICAL", assetId: "web-asset", assetType: "WEB" });
    const lowValueTarget = ranked({ id: "target-1", severity: "CRITICAL", assetId: "minor-asset", assetType: "SERVER" });
    const criticality = new Map([
      ["web-asset", "LOW" as const],
      ["minor-asset", "MEDIUM" as const],
    ]);

    expect(findAttackPathCandidates([entry, lowValueTarget], criticality)).toHaveLength(0);
  });

  it("excludes a non-internet-facing asset's finding from being an entry point regardless of severity", () => {
    const internalEntry = ranked({ id: "entry-1", severity: "CRITICAL", assetId: "internal-asset", assetType: "NETWORK" });
    const target = ranked({ id: "target-1", severity: "HIGH", assetId: "dc-asset", assetType: "SERVER" });
    const criticality = new Map([
      ["internal-asset", "LOW" as const],
      ["dc-asset", "CRITICAL" as const],
    ]);

    expect(findAttackPathCandidates([internalEntry, target], criticality)).toHaveLength(0);
  });

  it("returns an empty array, not an error, when there are no findings at all", () => {
    expect(findAttackPathCandidates([], new Map())).toEqual([]);
  });

  it("caps total candidates rather than returning every entry×target combination unbounded", () => {
    const entries = Array.from({ length: 8 }, (_, i) => ranked({ id: `entry-${i}`, severity: "CRITICAL", assetId: `web-${i}`, assetType: "WEB" }));
    const targets = Array.from({ length: 8 }, (_, i) => ranked({ id: `target-${i}`, severity: "HIGH", assetId: `dc-${i}`, assetType: "SERVER" }));
    const criticality = new Map<string, "LOW" | "CRITICAL">([
      ...entries.map((e) => [e.assetId, "LOW" as const] as const),
      ...targets.map((t) => [t.assetId, "CRITICAL" as const] as const),
    ]);

    const candidates = findAttackPathCandidates([...entries, ...targets], criticality);

    // 8 entries x 8 targets would be 64 uncapped — must stay well under that.
    expect(candidates.length).toBeLessThanOrEqual(10);
  });
});

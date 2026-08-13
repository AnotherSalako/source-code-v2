import { describe, expect, it } from "vitest";
import { titleSimilarity, computeExploitabilityScore, clusterFindings, RankedFinding } from "../src/modules/findings/clustering";

describe("titleSimilarity", () => {
  it("scores near-identical titles (same finding, different path) high", () => {
    expect(titleSimilarity("Missing CSP header on /login", "Missing CSP header on /admin/users")).toBeGreaterThanOrEqual(0.5);
  });

  it("scores unrelated titles low", () => {
    expect(titleSimilarity("Missing CSP header on /login", "Outdated jQuery version in use")).toBeLessThan(0.5);
  });

  it("is order-independent and self-identical", () => {
    const a = "SQL injection in /search endpoint";
    const b = "Reflected XSS in /profile page";
    expect(titleSimilarity(a, b)).toBe(titleSimilarity(b, a));
    expect(titleSimilarity(a, a)).toBe(1);
  });

  it("ignores port/ID numbers so two otherwise-identical titles differing only by a number still match", () => {
    expect(titleSimilarity("Open port 8080 exposes admin panel", "Open port 9090 exposes admin panel")).toBeGreaterThanOrEqual(0.5);
  });
});

describe("computeExploitabilityScore", () => {
  const baseFinding = {
    id: "f1",
    title: "Test finding",
    severity: "MEDIUM" as const,
    cvssScore: null,
    status: "OPEN" as const,
    assetId: "asset-1",
    discoveredAt: new Date(),
  };

  it("scores an internet-facing asset higher than an identical finding on a non-internet-facing one", () => {
    const web = computeExploitabilityScore(baseFinding, { type: "WEB", inScope: true });
    const network = computeExploitabilityScore(baseFinding, { type: "NETWORK", inScope: true });
    expect(web.internetFacing).toBe(true);
    expect(network.internetFacing).toBe(false);
    expect(web.score).toBeGreaterThan(network.score);
  });

  it("an out-of-scope WEB asset is not treated as internet-facing", () => {
    const result = computeExploitabilityScore(baseFinding, { type: "WEB", inScope: false });
    expect(result.internetFacing).toBe(false);
  });

  it("RETESTED_PASS and ACCEPTED_RISK zero out the score regardless of severity", () => {
    const critical = { ...baseFinding, severity: "CRITICAL" as const };
    expect(computeExploitabilityScore({ ...critical, status: "RETESTED_PASS" }, { type: "WEB", inScope: true }).score).toBe(0);
    expect(computeExploitabilityScore({ ...critical, status: "ACCEPTED_RISK" }, { type: "WEB", inScope: true }).score).toBe(0);
  });

  it("a failed retest scores the same as a freshly-open finding — still live risk", () => {
    const open = computeExploitabilityScore({ ...baseFinding, status: "OPEN" }, { type: "WEB", inScope: true });
    const failed = computeExploitabilityScore({ ...baseFinding, status: "RETESTED_FAIL" }, { type: "WEB", inScope: true });
    expect(failed.score).toBe(open.score);
  });

  it("an older open finding scores at least as high as a brand-new one, all else equal", () => {
    const fresh = computeExploitabilityScore(baseFinding, { type: "WEB", inScope: true });
    const old = computeExploitabilityScore(
      { ...baseFinding, discoveredAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000) },
      { type: "WEB", inScope: true }
    );
    expect(old.daysOpen).toBeGreaterThanOrEqual(59);
    expect(old.score).toBeGreaterThanOrEqual(fresh.score);
  });

  it("severity ordering holds: CRITICAL > HIGH > MEDIUM > LOW > INFO, all else equal", () => {
    const scores = (["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map(
      (severity) => computeExploitabilityScore({ ...baseFinding, severity }, { type: "SERVER", inScope: true }).score
    );
    for (let i = 1; i < scores.length; i++) expect(scores[i]).toBeGreaterThan(scores[i - 1]);
  });

  it("always returns a score clamped to 0-100", () => {
    const result = computeExploitabilityScore(
      { ...baseFinding, severity: "CRITICAL", cvssScore: 10, discoveredAt: new Date(0) },
      { type: "WEB", inScope: true }
    );
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });
});

describe("clusterFindings", () => {
  function ranked(overrides: Partial<RankedFinding> & { id: string; title: string }): RankedFinding {
    return {
      severity: "MEDIUM",
      cvssScore: null,
      status: "OPEN",
      assetId: "asset-1",
      discoveredAt: new Date(),
      exploitability: { score: 50, severityComponent: 40, internetFacing: false, daysOpen: 0, ageBonus: 0, statusWeight: 1 },
      ...overrides,
    };
  }

  it("groups near-duplicate titles into one cluster and reports the assets it spans", () => {
    const clusters = clusterFindings([
      ranked({ id: "a", title: "Missing CSP header on /login", assetId: "asset-1" }),
      ranked({ id: "b", title: "Missing CSP header on /admin", assetId: "asset-2" }),
      ranked({ id: "c", title: "Outdated jQuery version in use", assetId: "asset-1" }),
    ]);

    expect(clusters).toHaveLength(2);
    const cspCluster = clusters.find((c) => c.findingIds.includes("a"))!;
    expect(cspCluster.findingIds).toEqual(["a", "b"]);
    expect(cspCluster.assetCount).toBe(2);
  });

  it("sorts clusters by their highest member's exploitability score, descending", () => {
    const clusters = clusterFindings([
      ranked({ id: "low", title: "Outdated jQuery version in use", exploitability: { score: 10, severityComponent: 10, internetFacing: false, daysOpen: 0, ageBonus: 0, statusWeight: 1 } }),
      ranked({ id: "high", title: "Remote code execution via deserialization", exploitability: { score: 90, severityComponent: 90, internetFacing: true, daysOpen: 0, ageBonus: 0, statusWeight: 1 } }),
    ]);
    expect(clusters.map((c) => c.findingIds[0])).toEqual(["high", "low"]);
  });

  it("returns an empty array for no findings", () => {
    expect(clusterFindings([])).toEqual([]);
  });
});

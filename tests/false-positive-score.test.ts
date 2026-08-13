import { describe, expect, it } from "vitest";
import { computeFalsePositiveScore, FalsePositiveInput } from "../src/modules/findings/false-positive-score";

function finding(overrides: Partial<FalsePositiveInput> & { id: string; title: string }): FalsePositiveInput {
  return {
    cvssScore: 7.5,
    hasReproductionSteps: true,
    testType: "VULN_SCAN",
    ...overrides,
  } as FalsePositiveInput;
}

describe("computeFalsePositiveScore", () => {
  it("scores a human-verified pentest finding with full detail as LOW", () => {
    const target = finding({ id: "f1", title: "SQL injection", testType: "PENTEST", cvssScore: 9.1, hasReproductionSteps: true });
    const result = computeFalsePositiveScore(target, [target]);
    expect(result.likelihood).toBe("LOW");
    expect(result.humanVerified).toBe(true);
  });

  it("scores an automated scan finding with no reproduction steps and no CVSS as HIGH", () => {
    const target = finding({ id: "f1", title: "Weird header thing", testType: "VULN_SCAN", cvssScore: null, hasReproductionSteps: false });
    const result = computeFalsePositiveScore(target, [target]);
    expect(result.likelihood).toBe("HIGH");
    expect(result.humanVerified).toBe(false);
    expect(result.hasCvssScore).toBe(false);
    expect(result.hasReproductionSteps).toBe(false);
  });

  it("treats COMPLIANCE_REVIEW as human-verified, same as PENTEST", () => {
    const target = finding({ id: "f1", title: "Missing control X", testType: "COMPLIANCE_REVIEW" });
    const result = computeFalsePositiveScore(target, [target]);
    expect(result.humanVerified).toBe(true);
  });

  it("lowers the score when corroborated by similar findings elsewhere", () => {
    const target = finding({ id: "f1", title: "Missing CSP header on /login", testType: "VULN_SCAN" });
    const alone = computeFalsePositiveScore(target, [target]);

    const sibling1 = finding({ id: "f2", title: "Missing CSP header on /admin", testType: "VULN_SCAN" });
    const sibling2 = finding({ id: "f3", title: "Missing CSP header on /profile", testType: "VULN_SCAN" });
    const corroborated = computeFalsePositiveScore(target, [target, sibling1, sibling2]);

    expect(corroborated.corroboratedByCount).toBe(2);
    expect(corroborated.score).toBeLessThan(alone.score);
  });

  it("does not penalize a singleton finding beyond the baseline (absence of corroboration is not itself evidence of a false positive)", () => {
    const target = finding({ id: "f1", title: "Unique one-off issue", testType: "PENTEST", cvssScore: 8, hasReproductionSteps: true });
    const unrelated = finding({ id: "f2", title: "Completely different problem", testType: "PENTEST" });
    const result = computeFalsePositiveScore(target, [target, unrelated]);
    expect(result.corroboratedByCount).toBe(0);
    // Same as the human-verified-with-full-detail baseline case above.
    expect(result.score).toBe(15);
  });

  it("never scores outside 0-100", () => {
    const target = finding({ id: "f1", title: "x", testType: "VULN_SCAN", cvssScore: null, hasReproductionSteps: false });
    const many = Array.from({ length: 10 }, (_, i) => finding({ id: `s${i}`, title: "x" }));
    const result = computeFalsePositiveScore(target, [target, ...many]);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it("excludes the target finding itself from its own corroboration count", () => {
    const target = finding({ id: "f1", title: "Same exact title" });
    const result = computeFalsePositiveScore(target, [target]); // only itself in the list
    expect(result.corroboratedByCount).toBe(0);
  });
});

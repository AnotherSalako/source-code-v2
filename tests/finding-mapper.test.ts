import { describe, expect, it } from "vitest";
import { mapFindingToControls } from "../src/modules/compliance/finding-mapper";

describe("mapFindingToControls", () => {
  it("maps a SQL injection finding to secure coding (ISO27001 A.8.28)", () => {
    const mapped = mapFindingToControls("SQL injection in /search endpoint");
    expect(mapped).toContainEqual({ framework: "ISO27001", controlId: "A.8.28", controlName: "Secure coding" });
  });

  it("maps a weak-TLS finding to use of cryptography (ISO27001 A.8.24)", () => {
    const mapped = mapFindingToControls("Weak TLS cipher suites enabled");
    expect(mapped).toContainEqual({ framework: "ISO27001", controlId: "A.8.24", controlName: "Use of cryptography" });
  });

  it("maps an outdated-dependency finding to vulnerability management (ISO27001 A.8.8)", () => {
    const mapped = mapFindingToControls("Outdated jQuery version in use");
    expect(mapped).toContainEqual({ framework: "ISO27001", controlId: "A.8.8", controlName: "Management of technical vulnerabilities" });
  });

  it("is case-insensitive", () => {
    expect(mapFindingToControls("SQL INJECTION")).toEqual(mapFindingToControls("sql injection"));
  });

  it("returns multiple controls when a title matches more than one rule", () => {
    const mapped = mapFindingToControls("Hardcoded encryption key weakens session authentication");
    const controlIds = mapped.map((m) => m.controlId);
    expect(controlIds).toContain("A.8.5"); // "authentication" -> secure authentication
    expect(controlIds).toContain("A.8.24"); // "encrypt" -> use of cryptography
  });

  it("returns an empty array rather than forcing a match for an unrelated title", () => {
    expect(mapFindingToControls("Server responds slowly under load")).toEqual([]);
  });

  it("never mutates or duplicates entries across repeated calls", () => {
    const first = mapFindingToControls("SQL injection");
    const second = mapFindingToControls("SQL injection");
    expect(first).toEqual(second);
  });
});

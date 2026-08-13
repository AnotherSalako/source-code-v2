import { describe, it, expect } from "vitest";
import { parseNpmLockfile } from "../src/modules/sbom/sbom-parser";

function lockfile(packages: Record<string, { version?: string }>): string {
  return JSON.stringify({ name: "test", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "test" }, ...packages } });
}

describe("parseNpmLockfile", () => {
  it("extracts name and version from a top-level dependency", () => {
    const deps = parseNpmLockfile(lockfile({ "node_modules/lodash": { version: "4.17.15" } }));
    expect(deps).toEqual([{ name: "lodash", version: "4.17.15" }]);
  });

  it("handles scoped packages (@scope/name)", () => {
    const deps = parseNpmLockfile(lockfile({ "node_modules/@aws-sdk/client-s3": { version: "3.1110.0" } }));
    expect(deps).toEqual([{ name: "@aws-sdk/client-s3", version: "3.1110.0" }]);
  });

  it("extracts the innermost package name from a nested transitive dependency path", () => {
    const deps = parseNpmLockfile(lockfile({ "node_modules/a/node_modules/lodash": { version: "3.10.1" } }));
    expect(deps).toEqual([{ name: "lodash", version: "3.10.1" }]);
  });

  it("skips the root project entry (empty-string key)", () => {
    const deps = parseNpmLockfile(lockfile({}));
    expect(deps).toEqual([]);
  });

  it("skips entries with no version field", () => {
    const deps = parseNpmLockfile(lockfile({ "node_modules/weird": {} }));
    expect(deps).toEqual([]);
  });

  it("parses multiple dependencies", () => {
    const deps = parseNpmLockfile(
      lockfile({
        "node_modules/express": { version: "4.21.0" },
        "node_modules/lodash": { version: "4.17.15" },
      })
    );
    expect(deps).toHaveLength(2);
    expect(deps.map((d) => d.name).sort()).toEqual(["express", "lodash"]);
  });

  it("throws a clear error on invalid JSON", () => {
    expect(() => parseNpmLockfile("not json{{{")).toThrow("valid JSON");
  });

  it("throws a clear error when the packages field is missing (not a recognized lockfile)", () => {
    expect(() => parseNpmLockfile(JSON.stringify({ name: "test" }))).toThrow("Not a recognized package-lock.json");
  });

  it("caps at 500 dependencies rather than parsing unbounded", () => {
    const packages: Record<string, { version: string }> = {};
    for (let i = 0; i < 600; i++) packages[`node_modules/pkg-${i}`] = { version: "1.0.0" };
    const deps = parseNpmLockfile(lockfile(packages));
    expect(deps.length).toBe(500);
  });
});

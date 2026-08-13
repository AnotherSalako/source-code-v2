export interface SbomDependency {
  name: string;
  version: string;
}

const MAX_DEPENDENCIES = 500; // same bounding reasoning as MAX_CANDIDATES elsewhere — a real lockfile can list thousands of transitive deps; a partial real scan beats one that might never return

/**
 * Parses an npm `package-lock.json` (lockfileVersion 2 or 3 — both use the
 * flat top-level "packages" map keyed by path, unlike the old nested v1
 * "dependencies" tree). Resolved versions only, not the ranges in
 * package.json — OSV needs an exact version to match against, not "^4.17.0".
 *
 * Deliberately npm-only for v1. Not "SBOM done" in the CycloneDX/SPDX
 * sense — those are real, different formats this doesn't read — but a
 * real, exact-version dependency list is what the vulnerability lookup
 * actually needs, and this is the one this app's own dependency tree is
 * already an honest, ready-made test case for.
 */
export function parseNpmLockfile(raw: string): SbomDependency[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Not valid JSON — expected a package-lock.json file");
  }

  const doc = parsed as { lockfileVersion?: number; packages?: Record<string, { version?: string }> };
  if (!doc.packages || typeof doc.packages !== "object") {
    throw new Error('Not a recognized package-lock.json — expected a top-level "packages" object (lockfileVersion 2 or 3)');
  }

  const deps: SbomDependency[] = [];
  for (const [path, entry] of Object.entries(doc.packages)) {
    if (path === "" || !entry?.version) continue; // "" is the root project itself, not a dependency
    // Path shape: "node_modules/foo" or, for a nested transitive dep that
    // needed its own resolution, "node_modules/a/node_modules/foo" — the
    // package name is always everything after the LAST "node_modules/".
    const idx = path.lastIndexOf("node_modules/");
    if (idx === -1) continue;
    const name = path.slice(idx + "node_modules/".length);
    if (!name) continue;
    deps.push({ name, version: entry.version });
    if (deps.length >= MAX_DEPENDENCIES) break;
  }

  return deps;
}

import request from "supertest";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { seedUser, seedClient, seedEngagement, seedAsset, resetFakeDb } from "../helpers/test-app";

const { createApp } = await import("../../src/app");
const app = createApp();
const { findVulnerabilities } = await import("../../src/modules/sbom/osv-client");

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

function realLockfile(): Buffer {
  return Buffer.from(
    JSON.stringify({
      name: "test",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "test" },
        "node_modules/multer": { version: "1.4.5-lts.2" },
      },
    })
  );
}

beforeEach(() => {
  resetFakeDb();
  vi.clearAllMocks();
  seedClient({ id: CLIENT_A, name: "Acme" });
  seedClient({ id: CLIENT_B, name: "Beta Corp" });
  seedEngagement({ id: "eng-a", clientId: CLIENT_A });
  seedEngagement({ id: "eng-b", clientId: CLIENT_B });
  seedAsset({ id: "asset-a", engagementId: "eng-a", type: "SERVER", name: "API server" });
});

describe("POST /engagements/:id/assets/:assetId/sbom-scan", () => {
  it("403s for a non-admin role", async () => {
    seedUser({ email: "tech@acme.com", name: "Tech", role: "TECHNICAL_CLIENT", orgId: CLIENT_A });
    await request(app)
      .post("/engagements/eng-a/assets/asset-a/sbom-scan")
      .set("x-test-user", "tech@acme.com")
      .attach("file", realLockfile(), "package-lock.json")
      .expect(403);
  });

  it("400s when no file is attached", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app).post("/engagements/eng-a/assets/asset-a/sbom-scan").set("x-test-user", "admin@example.com").expect(400);
  });

  it("400s on a file that isn't a recognized lockfile", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const res = await request(app)
      .post("/engagements/eng-a/assets/asset-a/sbom-scan")
      .set("x-test-user", "admin@example.com")
      .attach("file", Buffer.from("not a lockfile"), "package-lock.json")
      .expect(400);
    expect(res.body.error).toContain("valid JSON");
  });

  it("404s for a nonexistent asset", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/engagements/eng-a/assets/does-not-exist/sbom-scan")
      .set("x-test-user", "admin@example.com")
      .attach("file", realLockfile(), "package-lock.json")
      .expect(404);
  });

  it("404s when the asset doesn't belong to the given engagement", async () => {
    seedAsset({ id: "asset-b", engagementId: "eng-b", type: "SERVER", name: "Other engagement's server" });
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    await request(app)
      .post("/engagements/eng-a/assets/asset-b/sbom-scan") // asset-b belongs to eng-b, not eng-a
      .set("x-test-user", "admin@example.com")
      .attach("file", realLockfile(), "package-lock.json")
      .expect(404);
  });

  it("returns dependencyCount and issues on a successful scan", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    vi.mocked(findVulnerabilities).mockResolvedValueOnce([
      {
        dependency: "multer",
        version: "1.4.5-lts.2",
        vulnerabilityId: "GHSA-44fp-w29j-9vj5",
        aliases: ["CVE-2024-xxxx"],
        summary: "Multer vulnerable to Denial of Service via memory leaks from unclosed streams",
        severity: "HIGH",
      },
    ]);

    const res = await request(app)
      .post("/engagements/eng-a/assets/asset-a/sbom-scan")
      .set("x-test-user", "admin@example.com")
      .attach("file", realLockfile(), "package-lock.json")
      .expect(200);

    expect(res.body.dependencyCount).toBe(1);
    expect(res.body.issues).toHaveLength(1);
    expect(res.body.issues[0].vulnerabilityId).toBe("GHSA-44fp-w29j-9vj5");
  });

  it("returns an empty issues array, not an error, for a lockfile with zero dependencies", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const emptyLockfile = Buffer.from(JSON.stringify({ name: "test", lockfileVersion: 3, packages: { "": { name: "test" } } }));

    const res = await request(app)
      .post("/engagements/eng-a/assets/asset-a/sbom-scan")
      .set("x-test-user", "admin@example.com")
      .attach("file", emptyLockfile, "package-lock.json")
      .expect(200);

    expect(res.body).toEqual({ dependencyCount: 0, issues: [] });
    // Zero dependencies means no OSV call was ever worth making.
    expect(findVulnerabilities).not.toHaveBeenCalled();
  });
});

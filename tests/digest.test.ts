import { describe, it, expect, beforeEach } from "vitest";
import {
  seedClient,
  seedEngagement,
  seedAsset,
  seedTest,
  seedFinding,
  seedWatchAlert,
  seedDiscoveryJob,
  seedDevice,
  resetFakeDb,
} from "./helpers/test-app";
import { buildWeeklyDigest } from "../src/modules/internal/digest.service";

beforeEach(() => {
  resetFakeDb();
});

function baseGraph() {
  seedClient({ id: "client-a", name: "Acme" });
  seedEngagement({ id: "eng-a", clientId: "client-a", status: "ACTIVE" });
  seedAsset({ id: "asset-a", engagementId: "eng-a", type: "WEB", name: "Site" });
  seedTest({ id: "test-a", engagementId: "eng-a", assetId: "asset-a", type: "PENTEST", testerId: "tester-1" });
}

describe("buildWeeklyDigest", () => {
  it("counts findings discovered within the window, grouped by severity, and excludes older ones", async () => {
    baseGraph();
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    seedFinding({ id: "f-new-1", testId: "test-a", assetId: "asset-a", title: "New HIGH", severity: "HIGH", discoveredAt: new Date() });
    seedFinding({ id: "f-new-2", testId: "test-a", assetId: "asset-a", title: "New HIGH 2", severity: "HIGH", discoveredAt: new Date() });
    seedFinding({ id: "f-new-3", testId: "test-a", assetId: "asset-a", title: "New LOW", severity: "LOW", discoveredAt: new Date() });
    seedFinding({ id: "f-old", testId: "test-a", assetId: "asset-a", title: "Old finding", severity: "CRITICAL", discoveredAt: new Date(since.getTime() - 24 * 60 * 60 * 1000) });

    const digest = await buildWeeklyDigest(since);

    expect(digest.totalNewFindings).toBe(3);
    expect(digest.newFindingsBySeverity.find((s) => s.severity === "HIGH")?.count).toBe(2);
    expect(digest.newFindingsBySeverity.find((s) => s.severity === "LOW")?.count).toBe(1);
    expect(digest.newFindingsBySeverity.find((s) => s.severity === "CRITICAL")).toBeUndefined();
  });

  it("counts watch alerts (drift) created within the window only", async () => {
    baseGraph();
    seedDiscoveryJob({ id: "job-a", engagementId: "eng-a", assetId: "asset-a" });
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    seedWatchAlert({ id: "alert-new", engagementId: "eng-a", discoveryJobId: "job-a", kind: "NEW_SUBDOMAIN", summary: "new", createdAt: new Date() });
    seedWatchAlert({ id: "alert-old", engagementId: "eng-a", discoveryJobId: "job-a", kind: "PORT_OPENED", summary: "old", createdAt: new Date(since.getTime() - 24 * 60 * 60 * 1000) });

    const digest = await buildWeeklyDigest(since);
    expect(digest.driftAlerts).toBe(1);
  });

  it("counts active engagements platform-wide", async () => {
    seedClient({ id: "client-a", name: "Acme" });
    seedEngagement({ id: "eng-active", clientId: "client-a", status: "ACTIVE" });
    seedEngagement({ id: "eng-closed", clientId: "client-a", status: "CLOSED" });

    const digest = await buildWeeklyDigest();
    expect(digest.activeEngagements).toBe(1);
  });

  it("flags ACTIVE agents that haven't checked in for 7+ days, with the owning client's name", async () => {
    seedClient({ id: "client-a", name: "Acme" });
    seedDevice({ id: "dev-stale", clientId: "client-a", name: "web-01", publicKeyBase64: "x", status: "ACTIVE", lastCheckInAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000) });
    seedDevice({ id: "dev-fresh", clientId: "client-a", name: "web-02", publicKeyBase64: "y", status: "ACTIVE", lastCheckInAt: new Date() });
    seedDevice({ id: "dev-never", clientId: "client-a", name: "web-03", publicKeyBase64: "z", status: "ACTIVE", lastCheckInAt: null });
    seedDevice({ id: "dev-revoked-stale", clientId: "client-a", name: "web-04", publicKeyBase64: "w", status: "REVOKED", lastCheckInAt: null });

    const digest = await buildWeeklyDigest();

    const names = digest.staleAgents.map((a) => a.deviceName).sort();
    expect(names).toEqual(["web-01", "web-03"]); // fresh check-in excluded; revoked device excluded regardless of staleness
    expect(digest.staleAgents.every((a) => a.clientName === "Acme")).toBe(true);
  });
});

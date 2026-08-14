import { describe, it, expect, beforeEach } from "vitest";
import { seedUsageEvent, seedAiUsageRecord, resetFakeDb } from "./helpers/test-app";
import { recordUsageEvent, getUsageSummary } from "../src/modules/usage/usage.service";

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
});

describe("getUsageSummary", () => {
  it("counts each kind independently and includes AI calls from AiUsageRecord", async () => {
    seedUsageEvent(CLIENT_A, "SCAN");
    seedUsageEvent(CLIENT_A, "SCAN");
    seedUsageEvent(CLIENT_A, "DISCOVERY");
    seedUsageEvent(CLIENT_A, "AGENT_CHECK_IN");
    seedAiUsageRecord(CLIENT_A);

    const summary = await getUsageSummary(CLIENT_A);
    expect(summary).toEqual({ scansRun: 2, discoveryRuns: 1, agentCheckIns: 1, aiCalls: 1 });
  });

  it("scopes counts per client — one org's events never bleed into another's", async () => {
    seedUsageEvent(CLIENT_A, "SCAN");
    seedUsageEvent(CLIENT_B, "SCAN");
    seedUsageEvent(CLIENT_B, "SCAN");

    const [a, b] = await Promise.all([getUsageSummary(CLIENT_A), getUsageSummary(CLIENT_B)]);
    expect(a.scansRun).toBe(1);
    expect(b.scansRun).toBe(2);
  });

  it("respects the `since` window, excluding older events", async () => {
    const now = Date.now();
    seedUsageEvent(CLIENT_A, "SCAN", { createdAt: new Date(now - 40 * 24 * 60 * 60 * 1000) }); // 40 days ago
    seedUsageEvent(CLIENT_A, "SCAN", { createdAt: new Date(now - 1 * 24 * 60 * 60 * 1000) }); // 1 day ago

    const allTime = await getUsageSummary(CLIENT_A);
    const last30Days = await getUsageSummary(CLIENT_A, new Date(now - 30 * 24 * 60 * 60 * 1000));

    expect(allTime.scansRun).toBe(2);
    expect(last30Days.scansRun).toBe(1);
  });
});

describe("recordUsageEvent", () => {
  it("a recorded event is immediately reflected in the summary", async () => {
    await recordUsageEvent(CLIENT_A, "SCAN");
    const summary = await getUsageSummary(CLIENT_A);
    expect(summary.scansRun).toBe(1);
  });
});

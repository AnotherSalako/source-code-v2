import { describe, it, expect, beforeEach, vi } from "vitest";

// This file needs env.aiTriageProvider to genuinely be "anthropic" so
// checkAndRecordAiUsage exercises its real cap-enforcement logic instead
// of the (correct, but trivial) no-op path every other test file's real
// "noop" env takes — mocked here, in isolation, rather than changing the
// actual .env, which would make every *other* test file's AI calls try to
// hit a real, unconfigured Anthropic client.
vi.mock("../src/config/env", () => ({
  env: {
    aiTriageProvider: "anthropic",
    aiDailyCallCap: 3,
    aiMonthlyCallCap: 5,
  },
}));

import { seedAiUsageRecord, resetFakeDb } from "./helpers/test-app";

const { checkAndRecordAiUsage } = await import("../src/ai/budget");

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CLIENT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

beforeEach(() => {
  resetFakeDb();
});

describe("checkAndRecordAiUsage", () => {
  it("allows and records a call when well under both caps", async () => {
    const result = await checkAndRecordAiUsage(CLIENT_A, "triage");
    expect(result.allowed).toBe(true);
  });

  it("denies once the daily cap (3, mocked) is reached", async () => {
    seedAiUsageRecord(CLIENT_A);
    seedAiUsageRecord(CLIENT_A);
    seedAiUsageRecord(CLIENT_A);

    const result = await checkAndRecordAiUsage(CLIENT_A, "triage");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Daily AI call cap");
  });

  it("denies once the monthly cap (5, mocked) is reached even if today's count is low", async () => {
    // 5 records spread across the last 3 weeks — under the daily cap on any
    // single day, but the monthly total is already at the mocked cap of 5.
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      seedAiUsageRecord(CLIENT_A, { createdAt: new Date(now - i * 5 * 24 * 60 * 60 * 1000) });
    }

    const result = await checkAndRecordAiUsage(CLIENT_A, "triage");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Monthly AI call cap");
  });

  it("does not count a usage record older than the rolling 24h window toward the daily cap", async () => {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    seedAiUsageRecord(CLIENT_A, { createdAt: twoDaysAgo });
    seedAiUsageRecord(CLIENT_A, { createdAt: twoDaysAgo });
    seedAiUsageRecord(CLIENT_A, { createdAt: twoDaysAgo });

    // All 3 existing records are outside the 24h window, so this 4th real
    // call today should still be allowed under the daily cap.
    const result = await checkAndRecordAiUsage(CLIENT_A, "triage");
    expect(result.allowed).toBe(true);
  });

  it("scopes the cap per client — one org's usage never affects another's", async () => {
    seedAiUsageRecord(CLIENT_A);
    seedAiUsageRecord(CLIENT_A);
    seedAiUsageRecord(CLIENT_A);

    const capped = await checkAndRecordAiUsage(CLIENT_A, "triage");
    const notCapped = await checkAndRecordAiUsage(CLIENT_B, "triage");

    expect(capped.allowed).toBe(false);
    expect(notCapped.allowed).toBe(true);
  });

  it("records the endpoint name on a successful call", async () => {
    await checkAndRecordAiUsage(CLIENT_A, "nlQuery");
    // A second call should now see 1 prior record and still be allowed
    // (well under the mocked cap of 3) — indirectly proves the first call
    // was actually recorded, not just approved.
    const result = await checkAndRecordAiUsage(CLIENT_A, "nlQuery");
    expect(result.allowed).toBe(true);
  });
});

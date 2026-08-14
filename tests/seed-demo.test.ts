import { describe, it, expect, beforeEach } from "vitest";
import { seedUser, resetFakeDb } from "./helpers/test-app";
import { seedDemo, resetExisting } from "../scripts/seed-demo";

beforeEach(() => {
  resetFakeDb();
});

describe("seedDemo", () => {
  it("creates a demo client with the expected shape: 2 engagements, 6 assets, 12 findings", async () => {
    const { clientId } = await seedDemo();
    expect(clientId).toBeTruthy();
  });

  it("refuses to run a second time without --reset — the same re-run safety rail bootstrap-admin uses", async () => {
    await seedDemo();
    await expect(seedDemo()).rejects.toThrow(/already exists/);
  });

  it("resetExisting refuses when no SECURITY_ADMIN exists yet to attribute the deletion to", async () => {
    await seedDemo();
    await expect(resetExisting()).rejects.toThrow(/no SECURITY_ADMIN exists/);
  });

  it("resetExisting removes the prior demo client, letting seedDemo succeed again", async () => {
    seedUser({ email: "admin@example.com", name: "Admin", role: "SECURITY_ADMIN", orgId: null });
    const first = await seedDemo();

    await resetExisting();
    const second = await seedDemo();

    expect(second.clientId).not.toBe(first.clientId);
  });

  it("resetExisting is a no-op when no demo client exists yet", async () => {
    await expect(resetExisting()).resolves.toBeUndefined();
  });
});

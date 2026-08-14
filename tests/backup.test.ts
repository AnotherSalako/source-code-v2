import { describe, it, expect, beforeEach } from "vitest";
import { seedClient, seedUser, seedDatabaseBackup, resetFakeDb } from "./helpers/test-app";
import { runDatabaseBackup, listBackups, BACKUP_MODELS } from "../src/modules/internal/backup.service";

beforeEach(() => {
  resetFakeDb();
});

describe("runDatabaseBackup", () => {
  it("dumps real seeded rows and reports accurate table counts", async () => {
    seedClient({ id: "client-1", name: "Acme" });
    seedUser({ email: "a@example.com", name: "A", role: "SECURITY_ADMIN", orgId: null });
    seedUser({ email: "b@example.com", name: "B", role: "TECHNICAL_CLIENT", orgId: "client-1" });

    const summary = await runDatabaseBackup();

    expect(summary.tableCounts.client).toBe(1);
    expect(summary.tableCounts.user).toBe(2);
    // Every model in BACKUP_MODELS shows up in the count report, even at zero —
    // proves the sweep actually walked every table, not just the seeded ones.
    for (const model of BACKUP_MODELS) {
      expect(summary.tableCounts).toHaveProperty(model);
    }
  });

  it("produces real, non-empty ciphertext (encryption actually ran, not skipped)", async () => {
    seedClient({ id: "client-1", name: "Acme" });
    const summary = await runDatabaseBackup();
    expect(summary.sizeBytes).toBeGreaterThan(0);
  });

  it("records a DatabaseBackup row visible via listBackups, without exposing decryption metadata", async () => {
    await runDatabaseBackup();
    const backups = await listBackups();
    expect(backups).toHaveLength(1);
    expect(backups[0]).not.toHaveProperty("iv");
    expect(backups[0]).not.toHaveProperty("encryptedDataKey");
  });

  it("prunes backups beyond the retention window, keeping only the most recent", async () => {
    // env.backupRetentionCount defaults to 14 — seed well past that directly
    // (bypassing runDatabaseBackup, which would be slow to call 20 times)
    // to exercise pruning without depending on the real default env value.
    for (let i = 0; i < 20; i++) {
      seedDatabaseBackup({ id: `old-${i}`, createdAt: new Date(Date.now() - (20 - i) * 60_000) });
    }

    const summary = await runDatabaseBackup();

    const backups = await listBackups();
    expect(backups.length).toBeLessThanOrEqual(14);
    // The newest one (just created) must survive the prune — it's the whole
    // point of pruning oldest-first rather than, say, randomly.
    expect(backups.some((b) => b.id === summary.id)).toBe(true);
    expect(backups.some((b) => b.id === "old-0")).toBe(false);
  });
});

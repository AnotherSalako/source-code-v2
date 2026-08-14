import zlib from "zlib";
import { promisify } from "util";
import { prisma } from "../../db/prisma";
import { kms, objectStorage, encryptBuffer } from "../../crypto";
import { newStorageKey } from "../../crypto/storage";
import { env } from "../../config/env";
import { logger } from "../../config/logger";

const gzip = promisify(zlib.gzip);

/**
 * Every model that holds real data, in FK-dependency order (parents before
 * children) — the same order a restore must INSERT in; DELETE during a
 * restore's wipe pass must run in the REVERSE of this order. Verified
 * against prisma/schema.prisma's actual @relation fields, not assumed from
 * declaration order. DatabaseBackup itself is deliberately excluded — a
 * backup doesn't need to contain the ledger of previous backups.
 */
export const BACKUP_MODELS = [
  "client",
  "user",
  "engagement",
  "asset",
  "test",
  "scanJob",
  "discoveryJob",
  "discoveredAsset",
  "watchAlert",
  "finding",
  "evidence",
  "complianceCheck",
  "report",
  "retest",
  "trainingSession",
  "keyRef",
  "auditLog",
  "agentCaKey",
  "enrollmentToken",
  "device",
  "cloudCredential",
  "clientKmsCredential",
  "aiUsageRecord",
  "usageEvent",
] as const;

export type BackupModel = (typeof BACKUP_MODELS)[number];

export interface BackupSummary {
  id: string;
  sizeBytes: number;
  tableCounts: Record<string, number>;
}

/**
 * Dumps every row of every table above to one gzip-compressed, envelope-
 * encrypted object in object storage, records the metadata needed to find
 * and decrypt it again (DatabaseBackup row), then prunes old backups beyond
 * env.backupRetentionCount. Called on a schedule (see internal/backup.routes.ts),
 * but safe to call directly too (scripts/backup-now.ts).
 */
export async function runDatabaseBackup(): Promise<BackupSummary> {
  const dump: Record<string, unknown[]> = {};
  const tableCounts: Record<string, number> = {};

  for (const model of BACKUP_MODELS) {
    // Cast needed: no single call signature is compatible across 22
    // structurally-different Prisma delegates at once, even though each one
    // individually accepts `findMany({})` fine — this loop's whole point is
    // walking every model generically rather than writing 22 near-identical
    // branches.
    const rows = await (prisma[model] as { findMany(args: object): Promise<unknown[]> }).findMany({});
    dump[model] = rows;
    tableCounts[model] = rows.length;
  }

  const json = Buffer.from(JSON.stringify(dump), "utf8");
  const compressed = (await gzip(json)) as Buffer;
  // AAD is a fixed string, not a per-backup ID — the ciphertext doesn't need
  // binding to its own not-yet-created DatabaseBackup row, just to "this is
  // a database backup" so it can never be swapped for some other ciphertext
  // blob in the same bucket and decrypt successfully.
  const encrypted = await encryptBuffer(kms, compressed, "database-backup");

  const storageKey = newStorageKey("backups");
  await objectStorage.put(storageKey, encrypted.ciphertext);

  const record = await prisma.databaseBackup.create({
    data: {
      storageKey,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      encryptedDataKey: encrypted.encryptedDataKey,
      kmsKeyId: encrypted.kmsKeyId,
      keyVersion: encrypted.keyVersion,
      sizeBytes: encrypted.ciphertext.length,
      tableCounts,
    },
  });

  const pruned = await pruneOldBackups();

  logger.info(
    { backupId: record.id, sizeBytes: record.sizeBytes, tableCounts, pruned },
    "Database backup complete"
  );

  return { id: record.id, sizeBytes: record.sizeBytes, tableCounts };
}

/** Keeps the most recent env.backupRetentionCount backups, deletes the rest (storage object + row). */
async function pruneOldBackups(): Promise<number> {
  const stale = await prisma.databaseBackup.findMany({
    orderBy: { createdAt: "desc" },
    skip: env.backupRetentionCount,
    select: { id: true, storageKey: true },
  });

  for (const backup of stale) {
    await objectStorage.delete(backup.storageKey);
    await prisma.databaseBackup.delete({ where: { id: backup.id } });
  }

  return stale.length;
}

export interface BackupListItem {
  id: string;
  sizeBytes: number;
  tableCounts: unknown;
  createdAt: Date;
}

/** Metadata only — never the ciphertext or its decryption key. */
export async function listBackups(): Promise<BackupListItem[]> {
  return prisma.databaseBackup.findMany({
    orderBy: { createdAt: "desc" },
    select: { id: true, sizeBytes: true, tableCounts: true, createdAt: true },
  });
}

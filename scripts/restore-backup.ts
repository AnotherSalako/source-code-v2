import "dotenv/config";
import zlib from "zlib";
import { promisify } from "util";
import { prisma } from "../src/db/prisma";
import { kms, objectStorage, decryptBuffer } from "../src/crypto";
import { BACKUP_MODELS, BackupModel } from "../src/modules/internal/backup.service";

const gunzip = promisify(zlib.gunzip);

// Restores every table from a backup produced by src/modules/internal/backup.service.ts.
// Deliberately a manually-run script, not an HTTP route: "wipe every table
// and reload it" is too destructive to expose over the network at all, even
// SECURITY_ADMIN-gated — this needs a real operator with real DATABASE_URL
// access making a deliberate call, the same trust boundary as bootstrap-admin.ts.
//
// Usage:
//   npx ts-node --transpile-only scripts/restore-backup.ts                  # inspect the latest backup, restore nothing
//   npx ts-node --transpile-only scripts/restore-backup.ts <backupId>       # inspect a specific backup
//   npx ts-node --transpile-only scripts/restore-backup.ts <backupId> --confirm-wipe-and-restore

async function loadBackup(backupId?: string) {
  const backup = backupId
    ? await prisma.databaseBackup.findUnique({ where: { id: backupId } })
    : (await prisma.databaseBackup.findMany({ orderBy: { createdAt: "desc" }, take: 1 }))[0];

  if (!backup) {
    throw new Error(backupId ? `No backup found with id ${backupId}` : "No backups exist yet");
  }

  const ciphertext = await objectStorage.get(backup.storageKey);
  const compressed = await decryptBuffer(
    kms,
    {
      ciphertext,
      iv: backup.iv,
      authTag: backup.authTag,
      encryptedDataKey: backup.encryptedDataKey,
      kmsKeyId: backup.kmsKeyId,
    },
    "database-backup"
  );
  const json = await gunzip(compressed);
  const dump = JSON.parse(json.toString("utf8")) as Record<BackupModel, unknown[]>;

  return { backup, dump };
}

async function restore(dump: Record<BackupModel, unknown[]>) {
  const ops: unknown[] = [];

  // Children before parents, so a foreign key never points at a row that's
  // about to be deleted out from under it mid-transaction.
  for (const model of [...BACKUP_MODELS].reverse()) {
    ops.push((prisma[model] as any).deleteMany({}));
  }
  // Then parents before children, matching BACKUP_MODELS' own order, for the
  // reverse reason — a child row's FK must already exist when it's inserted.
  for (const model of BACKUP_MODELS) {
    const rows = dump[model] ?? [];
    if (rows.length > 0) {
      ops.push((prisma[model] as any).createMany({ data: rows }));
    }
  }

  await prisma.$transaction(ops as any, { timeout: 120_000 });
}

async function cli() {
  const args = process.argv.slice(2);
  const confirmed = args.includes("--confirm-wipe-and-restore");
  const backupId = args.find((a) => !a.startsWith("--"));

  const { backup, dump } = await loadBackup(backupId);

  console.log(`Backup ${backup.id}`);
  console.log(`  created: ${backup.createdAt.toISOString()}`);
  console.log(`  size:    ${(backup.sizeBytes / 1024 / 1024).toFixed(2)} MB (compressed, encrypted)`);
  console.log("  table row counts:");
  for (const [table, count] of Object.entries(backup.tableCounts as Record<string, number>)) {
    console.log(`    ${table}: ${count}`);
  }

  if (!confirmed) {
    console.log(
      "\nDry run only — no data was touched. This backup decrypted and decompressed successfully, " +
        "which already confirms it's readable and intact.\n" +
        "To actually WIPE every table in this database and reload it from this backup, re-run with:\n" +
        `  npx ts-node --transpile-only scripts/restore-backup.ts ${backup.id} --confirm-wipe-and-restore`
    );
    return;
  }

  console.log("\n--confirm-wipe-and-restore passed — wiping and restoring all tables now...");
  await restore(dump);
  console.log("Restore complete.");
}

if (require.main === module) {
  cli()
    .catch((err) => {
      console.error("Restore failed:", err);
      process.exit(1);
    })
    .finally(() => prisma.$disconnect());
}

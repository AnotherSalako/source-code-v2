import "dotenv/config";
import { prisma } from "../src/db/prisma";
import { runDatabaseBackup } from "../src/modules/internal/backup.service";

// Manual on-demand trigger for the same backup src/modules/internal/backup.routes.ts
// runs daily via Vercel Cron — useful to take a backup right before a risky
// migration/deploy, or to verify the mechanism works without waiting for the
// schedule.
//
// Usage: npx ts-node --transpile-only scripts/backup-now.ts

async function cli() {
  const summary = await runDatabaseBackup();
  console.log(`Backup ${summary.id} complete — ${(summary.sizeBytes / 1024 / 1024).toFixed(2)} MB (compressed, encrypted)`);
  console.log("Table row counts:");
  for (const [table, count] of Object.entries(summary.tableCounts)) {
    console.log(`  ${table}: ${count}`);
  }
}

if (require.main === module) {
  cli()
    .catch((err) => {
      console.error("Backup failed:", err);
      process.exit(1);
    })
    .finally(() => prisma.$disconnect());
}

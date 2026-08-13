import "dotenv/config";
import { prisma } from "../src/db/prisma";
import { LocalKmsProvider } from "../src/crypto/kms";
import { AwsKmsProvider } from "../src/crypto/providers/aws-kms";
import { encryptField, decryptField, encryptBuffer, decryptBuffer, EncryptedField } from "../src/crypto/envelope";
import { objectStorage } from "../src/crypto";
import { newStorageKey } from "../src/crypto/storage";

// One-off migration: every *Enc field and every encrypted file blob was
// wrapped under the local dev CMK (LocalKmsProvider). This decrypts each one
// with the OLD provider and re-encrypts it with a real AWS KMS key — the
// built-in /internal/rotate-keys route can't do this itself, since it
// decrypts and re-encrypts with the SAME provider instance (for bumping key
// *versions* within one provider, not migrating across incompatible
// ciphertext formats). Run with DRY_RUN=true first — decrypts, re-encrypts
// in memory, and verifies the plaintext round-trips correctly, but writes
// nothing. Only re-run with DRY_RUN=false once that's clean.

const DRY_RUN = process.env.DRY_RUN !== "false";

const oldKms = new LocalKmsProvider(process.env.OLD_CMK_BASE64!, process.env.OLD_CMK_ID!, parseInt(process.env.OLD_CMK_VERSION!, 10));
const newKms = new AwsKmsProvider(process.env.NEW_AWS_REGION!, process.env.NEW_AWS_KMS_KEY_ID!, 1);

let fieldsMigrated = 0;
let filesMigrated = 0;
let errors = 0;

async function migrateField<T extends { id: string }>(
  label: string,
  rows: (T & Record<string, unknown>)[],
  column: string,
  aad: (row: T) => string
) {
  for (const row of rows) {
    const current = (row as any)[column] as EncryptedField | null;
    if (!current) continue;
    if (current.kmsKeyId === process.env.NEW_AWS_KMS_KEY_ID) continue; // already migrated, safe to re-run
    try {
      const plaintext = await decryptField(oldKms, current, aad(row));
      const reEncrypted = await encryptField(newKms, plaintext, aad(row));
      // Round-trip check before trusting it, dry run or not.
      const verify = await decryptField(newKms, reEncrypted, aad(row));
      if (verify !== plaintext) throw new Error("round-trip mismatch");

      if (!DRY_RUN) {
        await (prisma as any)[label].update({ where: { id: row.id }, data: { [column]: reEncrypted as any } });
      }
      fieldsMigrated++;
    } catch (err) {
      errors++;
      console.error(`FIELD FAILED ${label}.${column} id=${row.id}:`, err instanceof Error ? err.message : err);
    }
  }
}

async function migrateBuffer(
  label: string,
  id: string,
  storageKey: string,
  meta: { iv: string; authTag: string; encryptedDataKey: string; kmsKeyId: string },
  aad: string,
  onSuccess: (newMeta: { storageKey: string; iv: string; authTag: string; encryptedDataKey: string; kmsKeyId: string; keyVersion: number }) => Promise<void>
) {
  if (meta.kmsKeyId === process.env.NEW_AWS_KMS_KEY_ID) return; // already migrated, safe to re-run
  try {
    const ciphertext = await objectStorage.get(storageKey);
    const plaintext = await decryptBuffer(oldKms, { ciphertext, iv: meta.iv, authTag: meta.authTag, encryptedDataKey: meta.encryptedDataKey, kmsKeyId: meta.kmsKeyId }, aad);
    const reEncrypted = await encryptBuffer(newKms, plaintext, aad);
    const verify = await decryptBuffer(newKms, { ciphertext: reEncrypted.ciphertext, iv: reEncrypted.iv, authTag: reEncrypted.authTag, encryptedDataKey: reEncrypted.encryptedDataKey, kmsKeyId: reEncrypted.kmsKeyId }, aad);
    if (!verify.equals(plaintext)) throw new Error("round-trip mismatch");

    // Written under a fresh key rather than overwriting — put() deliberately
    // refuses to overwrite (upsert: false) as a safety default against
    // silently clobbering existing evidence on the app's normal write path.
    // The old ciphertext (now orphaned, encrypted under a key about to be
    // retired) is left in place rather than deleted — ObjectStorage has no
    // delete() method, and it's inert either way.
    const freshKey = newStorageKey(storageKey.slice(0, storageKey.lastIndexOf("/")));

    if (!DRY_RUN) {
      await objectStorage.put(freshKey, reEncrypted.ciphertext);
      await onSuccess({ storageKey: freshKey, iv: reEncrypted.iv, authTag: reEncrypted.authTag, encryptedDataKey: reEncrypted.encryptedDataKey, kmsKeyId: reEncrypted.kmsKeyId, keyVersion: reEncrypted.keyVersion });
    }
    filesMigrated++;
  } catch (err) {
    errors++;
    console.error(`FILE FAILED ${label} id=${id}:`, err instanceof Error ? err.message : err);
  }
}

async function main() {
  console.log(`=== ${DRY_RUN ? "DRY RUN" : "LIVE RUN"} ===`);

  const clients = await prisma.client.findMany();
  await migrateField("client", clients, "primaryContactEnc", () => "client:primaryContact");
  await migrateField("client", clients, "billingInfoEnc", () => "client:billingInfo");

  const engagements = await prisma.engagement.findMany();
  await migrateField("engagement", engagements, "assumptionsEnc", () => "engagement:assumptions");
  await migrateField("engagement", engagements, "exclusionsEnc", () => "engagement:exclusions");

  const assets = await prisma.asset.findMany();
  await migrateField("asset", assets, "identifierEnc", () => "asset:identifier");
  await migrateField("asset", assets, "notesEnc", () => "asset:notes");

  const findings = await prisma.finding.findMany();
  await migrateField("finding", findings, "descriptionEnc", () => "finding:description");
  await migrateField("finding", findings, "reproductionStepsEnc", () => "finding:reproductionSteps");
  await migrateField("finding", findings, "remediationGuidanceEnc", () => "finding:remediationGuidance");

  const scanJobs = await prisma.scanJob.findMany();
  await migrateField("scanJob", scanJobs, "rawResultEnc", () => "scanjob:rawResult");

  const complianceChecks = await prisma.complianceCheck.findMany();
  await migrateField("complianceCheck", complianceChecks, "notesEnc", () => "compliance:notes");

  const retests = await prisma.retest.findMany();
  await migrateField("retest", retests, "notesEnc", () => "retest:notes");

  const trainingSessions = await prisma.trainingSession.findMany();
  await migrateField("trainingSession", trainingSessions, "notesEnc", () => "training:notes");

  // Buffer-encrypted files
  const evidence = await prisma.evidence.findMany();
  for (const e of evidence) {
    await migrateBuffer("evidence", e.id, e.storageKey, e, `evidence:${e.findingId}`, async (m) => {
      await prisma.evidence.update({ where: { id: e.id }, data: { storageKey: m.storageKey, iv: m.iv, authTag: m.authTag, encryptedDataKey: m.encryptedDataKey, kmsKeyId: m.kmsKeyId, keyVersion: m.keyVersion } });
    });
  }

  const reports = await prisma.report.findMany();
  for (const r of reports) {
    await migrateBuffer("report", r.id, r.storageKey, r, `report:${r.engagementId}:${r.type}`, async (m) => {
      await prisma.report.update({ where: { id: r.id }, data: { storageKey: m.storageKey, iv: m.iv, authTag: m.authTag, encryptedDataKey: m.encryptedDataKey, kmsKeyId: m.kmsKeyId, keyVersion: m.keyVersion } });
    });
  }

  const engagementsWithAuthDoc = engagements.filter((e) => e.authorizationDocRef && e.authorizationDocIv);
  for (const e of engagementsWithAuthDoc) {
    await migrateBuffer(
      "engagement.authDoc",
      e.id,
      e.authorizationDocRef!,
      { iv: e.authorizationDocIv!, authTag: e.authorizationDocAuthTag!, encryptedDataKey: e.authorizationDocEncryptedDataKey!, kmsKeyId: e.authorizationDocKmsKeyId! },
      `authorization-doc:${e.id}`,
      async (m) => {
        await prisma.engagement.update({
          where: { id: e.id },
          data: {
            authorizationDocRef: m.storageKey,
            authorizationDocIv: m.iv,
            authorizationDocAuthTag: m.authTag,
            authorizationDocEncryptedDataKey: m.encryptedDataKey,
            authorizationDocKmsKeyId: m.kmsKeyId,
            authorizationDocKeyVersion: m.keyVersion,
          },
        });
      }
    );
  }

  console.log(`\n=== Result: ${fieldsMigrated} fields, ${filesMigrated} files migrated, ${errors} errors ===`);
  if (errors > 0) process.exitCode = 1;
}

main()
  .catch((err) => {
    console.error("Migration failed:", err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());

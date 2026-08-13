import { PrismaClient } from "@prisma/client";
import { KmsProvider } from "./kms";
import { decryptField, encryptField, EncryptedField } from "./envelope";
import { writeAuditLog } from "../modules/audit/audit.service";

/**
 * Re-wraps one field under a fresh DEK on the current CMK version. Safe to run
 * online: decrypt-then-reencrypt happens inside a transaction against a single
 * row, so a record is never left partially migrated. Call this from a scheduled
 * batch job (e.g. nightly, walking KeyRef rows where keyVersion < current),
 * never inline on a request path.
 */
export async function rotateFieldKey(
  prisma: PrismaClient,
  kms: KmsProvider,
  args: {
    table: string; // used only to build the KeyRef resourceType label, e.g. "finding.descriptionEnc"
    id: string;
    column: string;
    aad: string;
    getField: () => Promise<EncryptedField | null>;
    setField: (next: EncryptedField) => Promise<void>;
  }
): Promise<{ rotated: boolean }> {
  const current = await args.getField();
  if (!current) return { rotated: false };
  if (current.keyVersion === kms.currentKeyVersion() && current.kmsKeyId === kms.currentKeyId()) {
    return { rotated: false }; // already on current key, nothing to do
  }
  // A record already wrapped under a key that isn't the system default is
  // on some client's dedicated per-tenant key (src/crypto/tenant.ts) — this
  // sweep only knows the system key's current id/version, so blindly
  // "rotating" it here would silently re-wrap it back onto the shared
  // system key, undoing the tenant assignment. Skip it instead; rotating a
  // tenant's own key to a new version is real, separate future work, not
  // something to fake by falling back to the wrong key.
  if (current.kmsKeyId !== kms.currentKeyId()) {
    return { rotated: false };
  }

  const plaintext = await decryptField(kms, current, args.aad);
  const reEncrypted = await encryptField(kms, plaintext, args.aad);
  await args.setField(reEncrypted);

  await prisma.keyRef.updateMany({
    where: { resourceType: `${args.table}.${args.column}`, resourceId: args.id, status: "ACTIVE" },
    data: { status: "RETIRED", retiredAt: new Date() },
  });
  await prisma.keyRef.create({
    data: {
      purpose: "DB_FIELD",
      kmsKeyId: reEncrypted.kmsKeyId,
      keyVersion: reEncrypted.keyVersion,
      resourceType: `${args.table}.${args.column}`,
      resourceId: args.id,
      status: "ACTIVE",
    },
  });

  await writeAuditLog(prisma, {
    userId: null,
    action: "UPDATE",
    resourceType: `${args.table}.${args.column}`,
    resourceId: args.id,
    result: "SUCCESS",
  });

  return { rotated: true };
}

// Batch size per table per sweep — keeps one invocation fast and bounded,
// important on a serverless function with a request timeout (see
// src/modules/internal/rotation.routes.ts, which calls this on a schedule).
// A field only needs rotating once per CMK/key-version change, so repeated
// runs converge even at a small batch size — this doesn't need to finish
// the whole database in one call.
const BATCH_SIZE = 25;

interface SweepResult {
  table: string;
  column: string;
  scanned: number;
  rotated: number;
}

/**
 * Walks every encrypted field in the schema, rotating any whose embedded
 * keyVersion/kmsKeyId doesn't match the KMS provider's current key. AAD
 * strings here MUST exactly match what each route uses to encrypt/decrypt
 * that column (see the grep-verified list this was built from) — a mismatch
 * breaks decryption for that field, not just rotation.
 */
export async function rotateAllFields(prisma: PrismaClient, kms: KmsProvider): Promise<SweepResult[]> {
  const results: SweepResult[] = [];

  async function sweep(
    table: string,
    column: string,
    aad: string | ((id: string) => string),
    rows: { id: string; field: EncryptedField | null }[],
    setField: (id: string, next: EncryptedField) => Promise<void>
  ) {
    let rotated = 0;
    for (const row of rows) {
      if (!row.field) continue;
      const result = await rotateFieldKey(prisma, kms, {
        table,
        id: row.id,
        column,
        aad: typeof aad === "function" ? aad(row.id) : aad,
        getField: async () => row.field,
        setField: (next) => setField(row.id, next),
      });
      if (result.rotated) rotated++;
    }
    results.push({ table, column, scanned: rows.length, rotated });
  }

  const clients = await prisma.client.findMany({ take: BATCH_SIZE, select: { id: true, primaryContactEnc: true, billingInfoEnc: true } });
  await sweep("client", "primaryContactEnc", "client:primaryContact", clients.map((c) => ({ id: c.id, field: c.primaryContactEnc as any })), (id, f) => prisma.client.update({ where: { id }, data: { primaryContactEnc: f as any } }).then(() => {}));
  await sweep("client", "billingInfoEnc", "client:billingInfo", clients.map((c) => ({ id: c.id, field: c.billingInfoEnc as any })), (id, f) => prisma.client.update({ where: { id }, data: { billingInfoEnc: f as any } }).then(() => {}));

  const engagements = await prisma.engagement.findMany({ take: BATCH_SIZE, select: { id: true, assumptionsEnc: true, exclusionsEnc: true } });
  await sweep("engagement", "assumptionsEnc", "engagement:assumptions", engagements.map((e) => ({ id: e.id, field: e.assumptionsEnc as any })), (id, f) => prisma.engagement.update({ where: { id }, data: { assumptionsEnc: f as any } }).then(() => {}));
  await sweep("engagement", "exclusionsEnc", "engagement:exclusions", engagements.map((e) => ({ id: e.id, field: e.exclusionsEnc as any })), (id, f) => prisma.engagement.update({ where: { id }, data: { exclusionsEnc: f as any } }).then(() => {}));

  const assets = await prisma.asset.findMany({ take: BATCH_SIZE, select: { id: true, identifierEnc: true, notesEnc: true } });
  await sweep("asset", "identifierEnc", "asset:identifier", assets.map((a) => ({ id: a.id, field: a.identifierEnc as any })), (id, f) => prisma.asset.update({ where: { id }, data: { identifierEnc: f as any } }).then(() => {}));
  await sweep("asset", "notesEnc", "asset:notes", assets.map((a) => ({ id: a.id, field: a.notesEnc as any })), (id, f) => prisma.asset.update({ where: { id }, data: { notesEnc: f as any } }).then(() => {}));

  const findings = await prisma.finding.findMany({
    take: BATCH_SIZE,
    select: { id: true, descriptionEnc: true, reproductionStepsEnc: true, remediationGuidanceEnc: true },
  });
  await sweep("finding", "descriptionEnc", "finding:description", findings.map((f) => ({ id: f.id, field: f.descriptionEnc as any })), (id, f) => prisma.finding.update({ where: { id }, data: { descriptionEnc: f as any } }).then(() => {}));
  await sweep("finding", "reproductionStepsEnc", "finding:reproductionSteps", findings.map((f) => ({ id: f.id, field: f.reproductionStepsEnc as any })), (id, f) => prisma.finding.update({ where: { id }, data: { reproductionStepsEnc: f as any } }).then(() => {}));
  await sweep("finding", "remediationGuidanceEnc", "finding:remediationGuidance", findings.map((f) => ({ id: f.id, field: f.remediationGuidanceEnc as any })), (id, f) => prisma.finding.update({ where: { id }, data: { remediationGuidanceEnc: f as any } }).then(() => {}));

  const complianceChecks = await prisma.complianceCheck.findMany({ take: BATCH_SIZE, select: { id: true, notesEnc: true } });
  await sweep("complianceCheck", "notesEnc", "compliance:notes", complianceChecks.map((c) => ({ id: c.id, field: c.notesEnc as any })), (id, f) => prisma.complianceCheck.update({ where: { id }, data: { notesEnc: f as any } }).then(() => {}));

  const retests = await prisma.retest.findMany({ take: BATCH_SIZE, select: { id: true, notesEnc: true } });
  await sweep("retest", "notesEnc", "retest:notes", retests.map((r) => ({ id: r.id, field: r.notesEnc as any })), (id, f) => prisma.retest.update({ where: { id }, data: { notesEnc: f as any } }).then(() => {}));

  const trainingSessions = await prisma.trainingSession.findMany({ take: BATCH_SIZE, select: { id: true, notesEnc: true } });
  await sweep("trainingSession", "notesEnc", "training:notes", trainingSessions.map((t) => ({ id: t.id, field: t.notesEnc as any })), (id, f) => prisma.trainingSession.update({ where: { id }, data: { notesEnc: f as any } }).then(() => {}));

  // No more User.mfaSecretEnc to rotate — Clerk owns credentials/MFA now,
  // there's nothing encrypted on the User table itself anymore.

  return results;
}

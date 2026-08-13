import { PrismaClient } from "@prisma/client";
import { objectStorage } from "../../crypto";
import { logger } from "../../config/logger";
import { writeAuditLog } from "../audit/audit.service";

export interface ClientDeletionResult {
  clientId: string;
  clientName: string;
  deletedCounts: Record<string, number>;
  storageKeysDeleted: number;
  storageKeysFailed: number;
}

/**
 * Hard-deletes a Client and everything scoped under it — the "right to be
 * forgotten" path referenced in the DPA. Unlike the single-User DELETE route
 * (src/modules/users/users.routes.ts), this walks the *entire* dependency
 * graph rooted at Client, since none of these FKs are onDelete: Cascade
 * (Prisma defaults to Restrict for required relations) — deleting Client
 * directly would just throw a foreign key violation.
 *
 * AuditLog rows are deliberately left alone, same precedent as the User
 * delete route: they're append-only accountability records, not the
 * client's own data, and AuditLog.userId/resourceId are just informational
 * strings/nullable FKs, not something this flow needs to touch. A final
 * AuditLog entry documenting the deletion itself is written after the fact.
 *
 * DB rows are removed inside one transaction (all-or-nothing). Object
 * storage files are deleted best-effort afterward — S3-style stores have no
 * cross-row transactionality with Postgres, and leaving an orphaned
 * ciphertext blob with no DB row pointing at it is a containable failure
 * mode (nothing can ever decrypt or serve it again, since the DB row that
 * held its wrapped key is already gone) whereas blocking the whole erasure
 * on a flaky storage API is not.
 */
export async function deleteClientData(prisma: PrismaClient, clientId: string, performedByUserId: string): Promise<ClientDeletionResult> {
  const client = await prisma.client.findUniqueOrThrow({ where: { id: clientId } });

  const engagements = await prisma.engagement.findMany({ where: { clientId }, select: { id: true, authorizationDocRef: true } });
  const engagementIds = engagements.map((e) => e.id);

  const [tests, assets, evidenceRows, reportRows] = await Promise.all([
    prisma.test.findMany({ where: { engagementId: { in: engagementIds } }, select: { id: true } }),
    prisma.asset.findMany({ where: { engagementId: { in: engagementIds } }, select: { id: true } }),
    prisma.evidence.findMany({ where: { finding: { test: { engagementId: { in: engagementIds } } } }, select: { id: true, storageKey: true } }),
    prisma.report.findMany({ where: { engagementId: { in: engagementIds } }, select: { id: true, storageKey: true } }),
  ]);
  const testIds = tests.map((t) => t.id);
  const assetIds = assets.map((a) => a.id);
  const findings = await prisma.finding.findMany({ where: { testId: { in: testIds } }, select: { id: true } });
  const findingIds = findings.map((f) => f.id);

  const storageKeys = [
    ...evidenceRows.map((e) => e.storageKey),
    ...reportRows.map((r) => r.storageKey),
    ...engagements.map((e) => e.authorizationDocRef).filter((k): k is string => !!k),
  ];

  const deletedCounts: Record<string, number> = {};

  await prisma.$transaction(async (tx) => {
    deletedCounts.retest = (await tx.retest.deleteMany({ where: { findingId: { in: findingIds } } })).count;
    deletedCounts.evidence = (await tx.evidence.deleteMany({ where: { findingId: { in: findingIds } } })).count;
    deletedCounts.scanJob = (await tx.scanJob.deleteMany({ where: { engagementId: { in: engagementIds } } })).count;
    deletedCounts.finding = (await tx.finding.deleteMany({ where: { testId: { in: testIds } } })).count;
    deletedCounts.complianceCheck = (await tx.complianceCheck.deleteMany({ where: { engagementId: { in: engagementIds } } })).count;
    deletedCounts.report = (await tx.report.deleteMany({ where: { engagementId: { in: engagementIds } } })).count;
    deletedCounts.trainingSession = (await tx.trainingSession.deleteMany({ where: { engagementId: { in: engagementIds } } })).count;
    deletedCounts.test = (await tx.test.deleteMany({ where: { id: { in: testIds } } })).count;
    deletedCounts.asset = (await tx.asset.deleteMany({ where: { id: { in: assetIds } } })).count;
    deletedCounts.engagement = (await tx.engagement.deleteMany({ where: { id: { in: engagementIds } } })).count;
    deletedCounts.user = (await tx.user.deleteMany({ where: { orgId: clientId } })).count;

    const staleKeyRefResourceIds = [...findingIds, ...evidenceRows.map((e) => e.id), ...reportRows.map((r) => r.id), ...engagementIds, ...assetIds, ...testIds, clientId];
    deletedCounts.keyRef = (await tx.keyRef.deleteMany({ where: { resourceId: { in: staleKeyRefResourceIds } } })).count;

    deletedCounts.client = (await tx.client.deleteMany({ where: { id: clientId } })).count;
  });

  let storageKeysDeleted = 0;
  let storageKeysFailed = 0;
  for (const key of storageKeys) {
    try {
      await objectStorage.delete(key);
      storageKeysDeleted++;
    } catch (err) {
      storageKeysFailed++;
      logger.error({ err, key, clientId }, "Client deletion: failed to remove object storage file (DB row already gone)");
    }
  }

  await writeAuditLog(prisma, {
    userId: performedByUserId,
    action: "DELETE",
    resourceType: "client.erasure",
    resourceId: clientId,
    result: "SUCCESS",
  });

  logger.info({ clientId, clientName: client.name, deletedCounts, storageKeysDeleted, storageKeysFailed }, "Client data erasure complete");

  return { clientId, clientName: client.name, deletedCounts, storageKeysDeleted, storageKeysFailed };
}

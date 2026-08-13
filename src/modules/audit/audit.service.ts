import { AuditAction, AuditResult, PrismaClient } from "@prisma/client";

export interface AuditEntry {
  userId: string | null;
  action: AuditAction;
  resourceType: string;
  resourceId: string | null;
  result: AuditResult;
  engagementId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Append-only by convention: no route in this codebase should ever call
 * prisma.auditLog.update/delete. Call this BEFORE returning decrypted data
 * (log the access attempt, not just the outcome) so a crash mid-response
 * still leaves a trail.
 */
export async function writeAuditLog(prisma: PrismaClient, entry: AuditEntry): Promise<void> {
  await prisma.auditLog.create({
    data: {
      userId: entry.userId,
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId,
      engagementId: entry.engagementId ?? null,
      ipAddress: entry.ipAddress ?? null,
      userAgent: entry.userAgent ?? null,
      result: entry.result,
    },
  });
}

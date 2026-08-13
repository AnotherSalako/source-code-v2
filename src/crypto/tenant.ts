import { PrismaClient } from "@prisma/client";
import { DataKeyResult, KmsProvider } from "./kms";
import { kms as systemKms } from "./index";
import { prisma as defaultPrisma } from "../db/prisma";

/**
 * Wraps the system KmsProvider, pinning `generateDataKey` to one client's
 * dedicated key — or falling back to the system default when that client
 * hasn't been assigned one yet (see Client.kmsKeyId in schema.prisma).
 * `decryptDataKey` is untouched: it already carries whatever keyId the
 * ciphertext was actually wrapped under (tenant or system), same mechanism
 * key rotation already relies on, so this class has no decrypt-side logic
 * of its own — every route calls the same `decryptField`/`decryptBuffer`
 * either way, tenant-scoped or not.
 */
class TenantScopedKmsProvider implements KmsProvider {
  constructor(private readonly base: KmsProvider, private readonly tenantKeyId: string | null) {}

  currentKeyId(): string {
    return this.tenantKeyId ?? this.base.currentKeyId();
  }

  currentKeyVersion(): number {
    return this.base.currentKeyVersion();
  }

  generateDataKey(): Promise<DataKeyResult> {
    return this.base.generateDataKey(this.tenantKeyId ?? undefined);
  }

  decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer> {
    return this.base.decryptDataKey(encryptedDataKey, keyId);
  }
}

/**
 * Resolves the KmsProvider a given client's data should encrypt under —
 * their own dedicated key if PATCH /clients/:id/kms-key has assigned one,
 * the shared system key otherwise (the same behavior every client had
 * before this feature existed, so assigning a key is opt-in and additive,
 * never a forced migration).
 *
 * Call this once per request with the resource's *owning* client id (the
 * same id every route already resolves for its assertOwnOrg check — see
 * e.g. findings.routes.ts's `finding.test.engagement.clientId`), then pass
 * the result to encryptField/decryptField/encryptBuffer/decryptBuffer in
 * place of the bare `kms` import.
 */
export async function tenantKms(clientId: string, prisma: PrismaClient = defaultPrisma): Promise<KmsProvider> {
  const client = await prisma.client.findUnique({ where: { id: clientId }, select: { kmsKeyId: true } });
  return new TenantScopedKmsProvider(systemKms, client?.kmsKeyId ?? null);
}

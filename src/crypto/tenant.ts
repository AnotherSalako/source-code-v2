import { PrismaClient } from "@prisma/client";
import { DataKeyResult, KmsProvider } from "./kms";
import { kms as systemKms } from "./index";
import { decryptField } from "./envelope";
import { AwsKmsProvider } from "./providers/aws-kms";
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
 * Resolves the KmsProvider a given client's data should encrypt under, in
 * priority order:
 *
 * 1. BYOK (`ClientKmsCredential`, src/modules/clients/byok.routes.ts) — a
 *    real, separate AWS key in the *client's own* account, reached via
 *    their own credentials. This is the only tier that's genuinely BYOK;
 *    everything else below still ultimately uses this app's own AWS
 *    account, just a different key within it.
 * 2. `Client.kmsKeyId` — their own dedicated key, but one this app
 *    provisioned and still controls (PATCH /clients/:id/kms-key).
 * 3. The shared system key — the same behavior every client had before
 *    per-tenant keys existed at all.
 *
 * Every tier is opt-in and additive, never a forced migration — a client
 * with nothing configured gets tier 3, same as always. Call this once per
 * request with the resource's *owning* client id (the same id every route
 * already resolves for its assertOwnOrg check), then pass the result to
 * encryptField/decryptField/encryptBuffer/decryptBuffer in place of the
 * bare `kms` import.
 */
export async function tenantKms(clientId: string, prisma: PrismaClient = defaultPrisma): Promise<KmsProvider> {
  const byok = await prisma.clientKmsCredential.findUnique({ where: { clientId } });
  if (byok) {
    // Decrypted under the SYSTEM key, never a tenant key — see the model's
    // schema.prisma comment for why that's not optional.
    const accessKeyId = await decryptField(systemKms, byok.accessKeyIdEnc as any, `clientKmsCredential:accessKeyId`);
    const secretAccessKey = await decryptField(systemKms, byok.secretAccessKeyEnc as any, `clientKmsCredential:secretAccessKey`);
    return new AwsKmsProvider(byok.region, byok.keyId, 1, { accessKeyId, secretAccessKey });
  }

  const client = await prisma.client.findUnique({ where: { id: clientId }, select: { kmsKeyId: true } });
  return new TenantScopedKmsProvider(systemKms, client?.kmsKeyId ?? null);
}

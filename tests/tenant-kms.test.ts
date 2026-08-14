import { describe, it, expect, beforeEach } from "vitest";
import { seedClient, seedClientKmsCredential, resetFakeDb } from "./helpers/test-app";

const { tenantKms } = await import("../src/crypto/tenant");
const { AwsKmsProvider } = await import("../src/crypto/providers/aws-kms");
const { kms: systemKms } = await import("../src/crypto");

const CLIENT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

beforeEach(() => {
  resetFakeDb();
  seedClient({ id: CLIENT_A, name: "Acme" });
});

describe("tenantKms() resolution priority", () => {
  it("falls back to the system key when nothing is configured for the client", async () => {
    const resolved = await tenantKms(CLIENT_A);
    expect(resolved.currentKeyId()).toBe(systemKms.currentKeyId());
    expect(resolved).not.toBeInstanceOf(AwsKmsProvider);
  });

  it("uses Client.kmsKeyId when assigned and no BYOK credential exists", async () => {
    seedClient({ id: CLIENT_A, name: "Acme", kmsKeyId: "tenant-managed-key-id" });
    const resolved = await tenantKms(CLIENT_A);
    expect(resolved.currentKeyId()).toBe("tenant-managed-key-id");
    expect(resolved).not.toBeInstanceOf(AwsKmsProvider);
  });

  it("prefers a real BYOK credential over Client.kmsKeyId when both are configured", async () => {
    seedClient({ id: CLIENT_A, name: "Acme", kmsKeyId: "tenant-managed-key-id" });
    seedClientKmsCredential(CLIENT_A, {
      keyId: "arn:aws:kms:us-east-1:111111111111:key/client-owned",
      region: "us-east-1",
      accessKeyIdEnc: (await (await import("../src/crypto/envelope")).encryptField(systemKms, "AKIA_CLIENT", "clientKmsCredential:accessKeyId")) as any,
      secretAccessKeyEnc: (await (await import("../src/crypto/envelope")).encryptField(systemKms, "client-secret", "clientKmsCredential:secretAccessKey")) as any,
    });

    const resolved = await tenantKms(CLIENT_A);
    expect(resolved).toBeInstanceOf(AwsKmsProvider);
    expect(resolved.currentKeyId()).toBe("arn:aws:kms:us-east-1:111111111111:key/client-owned");
  });

  it("decrypts the stored BYOK credential correctly before using it (round-trips through real envelope encryption, not a stub)", async () => {
    const { encryptField } = await import("../src/crypto/envelope");
    seedClientKmsCredential(CLIENT_A, {
      keyId: "arn:aws:kms:us-east-1:111111111111:key/client-owned",
      accessKeyIdEnc: (await encryptField(systemKms, "AKIA_REAL_ROUNDTRIP", "clientKmsCredential:accessKeyId")) as any,
      secretAccessKeyEnc: (await encryptField(systemKms, "real-secret-roundtrip", "clientKmsCredential:secretAccessKey")) as any,
    });

    // No direct way to read the private credentials back off AwsKmsProvider
    // (by design — see its constructor) — what's actually being verified
    // here is that resolution didn't throw decrypting them, which it would
    // if the wrong KMS instance (a tenant key instead of the system key)
    // had been used to decrypt a credential encrypted under the system key.
    await expect(tenantKms(CLIENT_A)).resolves.toBeInstanceOf(AwsKmsProvider);
  });
});

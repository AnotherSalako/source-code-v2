import { describe, expect, it } from "vitest";
import crypto from "crypto";
import { LocalKmsProvider, KmsProvider, DataKeyResult } from "../src/crypto/kms";
import { encryptField, decryptField, encryptBuffer, decryptBuffer } from "../src/crypto/envelope";

function testKms() {
  return new LocalKmsProvider(crypto.randomBytes(32).toString("base64"), "test-cmk", 1);
}

describe("envelope field encryption (AES-256-GCM)", () => {
  it("round-trips plaintext", async () => {
    const kms = testKms();
    const encrypted = await encryptField(kms, "sensitive finding description", "finding:1:description");
    expect(encrypted.ciphertext).not.toContain("sensitive");
    const decrypted = await decryptField(kms, encrypted, "finding:1:description");
    expect(decrypted).toBe("sensitive finding description");
  });

  it("produces a distinct DEK per call (ciphertext differs for identical plaintext)", async () => {
    const kms = testKms();
    const a = await encryptField(kms, "same text", "ctx");
    const b = await encryptField(kms, "same text", "ctx");
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.encryptedDataKey).not.toBe(b.encryptedDataKey);
  });

  it("rejects a tampered ciphertext (GCM auth tag check)", async () => {
    const kms = testKms();
    const encrypted = await encryptField(kms, "do not tamper with me", "ctx");
    const tampered = { ...encrypted, ciphertext: Buffer.from("tampered!!!!!!!!").toString("base64") };
    await expect(decryptField(kms, tampered, "ctx")).rejects.toThrow();
  });

  it("rejects decryption under the wrong AAD context (binds ciphertext to its record)", async () => {
    const kms = testKms();
    const encrypted = await encryptField(kms, "bound to finding 1", "finding:1:description");
    await expect(decryptField(kms, encrypted, "finding:2:description")).rejects.toThrow();
  });

  it("fails to decrypt under a different CMK (simulates a stolen DB dump without KMS access)", async () => {
    const kmsA = testKms();
    const kmsB = testKms();
    const encrypted = await encryptField(kmsA, "secret", "ctx");
    await expect(decryptField(kmsB, encrypted, "ctx")).rejects.toThrow();
  });
});

// Mirrors src/crypto/tenant.ts's TenantScopedKmsProvider exactly (that class
// isn't exported — it's an internal implementation detail of tenantKms(),
// which needs a Prisma client to resolve a clientId to a keyId). This local
// double lets these tests exercise the real security property — one
// tenant's key can't decrypt another's data — without a DB in the loop.
class PinnedKms implements KmsProvider {
  constructor(private readonly base: KmsProvider, private readonly keyId: string) {}
  generateDataKey(): Promise<DataKeyResult> {
    return this.base.generateDataKey(this.keyId);
  }
  decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer> {
    return this.base.decryptDataKey(encryptedDataKey, keyId);
  }
  currentKeyId(): string {
    return this.keyId;
  }
  currentKeyVersion(): number {
    return this.base.currentKeyVersion();
  }
}

describe("per-tenant encryption keys (LocalKmsProvider HKDF derivation)", () => {
  it("generateDataKey(keyId) records that keyId on the result, distinct from the system default", async () => {
    const base = testKms(); // system default keyId is "test-cmk"
    const systemKey = await base.generateDataKey();
    const tenantAKey = await base.generateDataKey("tenant-a");
    expect(systemKey.keyId).toBe("test-cmk");
    expect(tenantAKey.keyId).toBe("tenant-a");
  });

  it("a DEK wrapped under one tenant's key cannot be unwrapped as a different tenant's key (real isolation, not just labeling)", async () => {
    const base = testKms();
    const tenantA = await base.generateDataKey("tenant-a");

    // Same root CMK, different keyId — must still fail. This is the actual
    // security property "unique key per client org" depends on.
    await expect(base.decryptDataKey(tenantA.encryptedDataKey, "tenant-b")).rejects.toThrow();
    await expect(base.decryptDataKey(tenantA.encryptedDataKey, "test-cmk")).rejects.toThrow();

    // But unwrapping under the exact keyId it was wrapped under always works.
    const unwrapped = await base.decryptDataKey(tenantA.encryptedDataKey, "tenant-a");
    expect(unwrapped.equals(tenantA.plaintextKey)).toBe(true);
  });

  it("two tenants' fields encrypt under provably different keys and each only decrypts correctly under its own", async () => {
    const base = testKms();
    const kmsForA = new PinnedKms(base, "tenant-a");
    const kmsForB = new PinnedKms(base, "tenant-b");

    const fieldA = await encryptField(kmsForA, "Client A's confidential contact info", "client:primaryContact");
    const fieldB = await encryptField(kmsForB, "Client B's confidential contact info", "client:primaryContact");

    expect(fieldA.kmsKeyId).toBe("tenant-a");
    expect(fieldB.kmsKeyId).toBe("tenant-b");
    expect(fieldA.ciphertext).not.toBe(fieldB.ciphertext);

    // Each round-trips correctly under the base provider (which is what
    // every route's plain decryptField(kms, ...) call actually uses) —
    // decrypting never needs to know which tenant a record belongs to,
    // only the record's own stored kmsKeyId, which travels with it.
    expect(await decryptField(base, fieldA, "client:primaryContact")).toBe("Client A's confidential contact info");
    expect(await decryptField(base, fieldB, "client:primaryContact")).toBe("Client B's confidential contact info");

    // A record encrypted for tenant A can never be silently decrypted as
    // tenant B's, or vice versa — swapping which EncryptedField's
    // encryptedDataKey/kmsKeyId pair you use is exactly what "stolen DB
    // dump, no KMS access" already covers, this just proves it also holds
    // across tenants sharing the same root CMK.
    const swapped = { ...fieldA, kmsKeyId: fieldB.kmsKeyId };
    await expect(decryptField(base, swapped, "client:primaryContact")).rejects.toThrow();
  });

  it("a client with no assigned key (kmsKeyId null) falls back to the system default — the pre-existing, unchanged behavior", async () => {
    const base = testKms();
    // tenantKms() passes `client?.kmsKeyId ?? null`, and TenantScopedKmsProvider
    // falls back to base.currentKeyId() when the pinned keyId is null — modeled
    // here by simply using the base provider directly (no pinning at all).
    const encrypted = await encryptField(base, "no dedicated key assigned yet", "ctx");
    expect(encrypted.kmsKeyId).toBe(base.currentKeyId());
    expect(await decryptField(base, encrypted, "ctx")).toBe("no dedicated key assigned yet");
  });
});

describe("envelope file/buffer encryption", () => {
  it("round-trips binary content", async () => {
    const kms = testKms();
    const original = crypto.randomBytes(4096);
    const encrypted = await encryptBuffer(kms, original, "evidence:1");
    expect(encrypted.ciphertext.equals(original)).toBe(false);
    const decrypted = await decryptBuffer(
      kms,
      { ...encrypted, ciphertext: encrypted.ciphertext },
      "evidence:1"
    );
    expect(decrypted.equals(original)).toBe(true);
  });
});

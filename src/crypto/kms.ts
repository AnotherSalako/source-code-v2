import crypto from "crypto";

export interface DataKeyResult {
  plaintextKey: Buffer; // 32-byte DEK, caller must zero after use
  encryptedDataKey: Buffer; // DEK wrapped by the CMK
  keyId: string;
  keyVersion: number;
}

// Swappable key-custody boundary: production deployments implement this
// against a real KMS (AWS KMS, GCP KMS, Azure Key Vault, Vault Transit) so the
// CMK never leaves managed hardware. See src/crypto/providers/aws-kms.example.ts
// for the shape of a production provider.
//
// `generateDataKey(keyId?)` — omit `keyId` to wrap under the provider's own
// default/system key (unchanged behavior, every pre-existing call site keeps
// working as-is); pass one to wrap under a *different* key instead — this is
// the hook per-tenant encryption (src/crypto/tenant.ts) uses to put a
// client's data under its own dedicated key rather than the shared system
// one. `decryptDataKey` already took a `keyId` before this existed, since a
// DEK must always be unwrapped under whatever key it was actually wrapped
// under — that's why only `generateDataKey` needed a new parameter here.
export interface KmsProvider {
  generateDataKey(keyId?: string): Promise<DataKeyResult>;
  decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer>;
  currentKeyId(): string;
  currentKeyVersion(): number;
}

// Non-secret, app-specific HKDF salt — binds derived per-tenant keys to this
// specific derivation scheme so they can never collide with a subkey some
// other use of the same root CMK might derive. Not a secret; HKDF salts
// never need to be.
const TENANT_KEY_HKDF_SALT = Buffer.from("jupiter-tenant-kms-v1");

/**
 * Local-development KMS stand-in. Wraps DEKs with a CMK read from env,
 * using AES-256-GCM for the wrap step itself. This keeps the envelope-encryption
 * *pattern* identical to production (app code never touches a raw CMK-equivalent
 * outside this module) while requiring no cloud account to run locally.
 *
 * Per-tenant keys (src/crypto/tenant.ts) are simulated here via HKDF: a
 * `keyId` that isn't the system default derives a distinct 32-byte subkey
 * from the one root CMK, keyed on that exact `keyId` string, rather than
 * requiring a separately-provisioned key per tenant the way real KMS does
 * in production (AwsKmsProvider — see providers/aws-kms.ts). HKDF's
 * security property is what makes this sound: knowing one derived subkey
 * (or even many) reveals nothing about the root CMK or about any other
 * tenant's subkey. This is still dev-only key *custody* — the same caveat
 * that already applied to the single-key version applies per-tenant too.
 *
 * DO NOT use this in production — the "CMK" here is a static env var, not
 * hardware-custodied, access-controlled key material.
 */
export class LocalKmsProvider implements KmsProvider {
  private readonly cmk: Buffer;
  private readonly keyId: string;
  private readonly keyVersion: number;

  constructor(cmkBase64: string, keyId: string, keyVersion: number) {
    const cmk = Buffer.from(cmkBase64, "base64");
    if (cmk.length !== 32) {
      throw new Error("CMK_BASE64 must decode to exactly 32 bytes (AES-256)");
    }
    this.cmk = cmk;
    this.keyId = keyId;
    this.keyVersion = keyVersion;
  }

  currentKeyId(): string {
    return this.keyId;
  }

  currentKeyVersion(): number {
    return this.keyVersion;
  }

  async generateDataKey(keyId?: string): Promise<DataKeyResult> {
    const targetKeyId = keyId ?? this.keyId;
    const plaintextKey = crypto.randomBytes(32);
    const encryptedDataKey = this.wrap(plaintextKey, targetKeyId);
    return {
      plaintextKey,
      encryptedDataKey,
      keyId: targetKeyId,
      keyVersion: this.keyVersion,
    };
  }

  async decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer> {
    return this.unwrap(encryptedDataKey, keyId);
  }

  /** The system default key uses the raw CMK unchanged (byte-identical to before per-tenant keys existed); any other keyId derives a distinct subkey. */
  private resolveWrappingKey(keyId: string): Buffer {
    if (keyId === this.keyId) return this.cmk;
    return Buffer.from(crypto.hkdfSync("sha256", this.cmk, TENANT_KEY_HKDF_SALT, keyId, 32));
  }

  private wrap(plaintextKey: Buffer, keyId: string): Buffer {
    const wrappingKey = this.resolveWrappingKey(keyId);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", wrappingKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
    const authTag = cipher.getAuthTag();
    // pack iv(12) | authTag(16) | ciphertext(32) into one buffer
    return Buffer.concat([iv, authTag, ciphertext]);
  }

  private unwrap(wrapped: Buffer, keyId: string): Buffer {
    const wrappingKey = this.resolveWrappingKey(keyId);
    const iv = wrapped.subarray(0, 12);
    const authTag = wrapped.subarray(12, 28);
    const ciphertext = wrapped.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", wrappingKey, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
}

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
export interface KmsProvider {
  generateDataKey(): Promise<DataKeyResult>;
  decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer>;
  currentKeyId(): string;
  currentKeyVersion(): number;
}

/**
 * Local-development KMS stand-in. Wraps DEKs with a CMK read from env,
 * using AES-256-GCM for the wrap step itself. This keeps the envelope-encryption
 * *pattern* identical to production (app code never touches a raw CMK-equivalent
 * outside this module) while requiring no cloud account to run locally.
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

  async generateDataKey(): Promise<DataKeyResult> {
    const plaintextKey = crypto.randomBytes(32);
    const encryptedDataKey = this.wrap(plaintextKey);
    return {
      plaintextKey,
      encryptedDataKey,
      keyId: this.keyId,
      keyVersion: this.keyVersion,
    };
  }

  async decryptDataKey(encryptedDataKey: Buffer, keyId: string): Promise<Buffer> {
    if (keyId !== this.keyId) {
      throw new Error(
        `No local CMK available for keyId "${keyId}" (have "${this.keyId}"). ` +
          "In production this is where retired CMK versions would still need to be reachable for old records."
      );
    }
    return this.unwrap(encryptedDataKey);
  }

  private wrap(plaintextKey: Buffer): Buffer {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.cmk, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintextKey), cipher.final()]);
    const authTag = cipher.getAuthTag();
    // pack iv(12) | authTag(16) | ciphertext(32) into one buffer
    return Buffer.concat([iv, authTag, ciphertext]);
  }

  private unwrap(wrapped: Buffer): Buffer {
    const iv = wrapped.subarray(0, 12);
    const authTag = wrapped.subarray(12, 28);
    const ciphertext = wrapped.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.cmk, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
}

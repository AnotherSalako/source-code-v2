import crypto from "crypto";
import { KmsProvider } from "./kms";

// Shape persisted in Postgres `Json` columns for every `*Enc` field.
export interface EncryptedField {
  ciphertext: string; // base64
  iv: string; // base64, 12 bytes
  authTag: string; // base64, 16 bytes
  encryptedDataKey: string; // base64, DEK wrapped by the CMK
  kmsKeyId: string;
  keyVersion: number;
}

export interface EncryptedBuffer {
  ciphertext: Buffer;
  iv: string; // base64
  authTag: string; // base64
  encryptedDataKey: string; // base64
  kmsKeyId: string;
  keyVersion: number;
}

/**
 * Encrypts one field's plaintext under a fresh, single-use DEK (envelope
 * encryption), then wipes the DEK from memory. `aad` binds the ciphertext to
 * its record so a ciphertext copied onto a different row fails to decrypt —
 * always pass something like `finding:${id}:description`.
 */
export async function encryptField(
  kms: KmsProvider,
  plaintext: string,
  aad: string
): Promise<EncryptedField> {
  const { plaintextKey, encryptedDataKey, keyId, keyVersion } = await kms.generateDataKey();
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", plaintextKey, iv);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      encryptedDataKey: encryptedDataKey.toString("base64"),
      kmsKeyId: keyId,
      keyVersion,
    };
  } finally {
    plaintextKey.fill(0);
  }
}

export async function decryptField(
  kms: KmsProvider,
  field: EncryptedField,
  aad: string
): Promise<string> {
  const plaintextKey = await kms.decryptDataKey(
    Buffer.from(field.encryptedDataKey, "base64"),
    field.kmsKeyId
  );
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", plaintextKey, Buffer.from(field.iv, "base64"));
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(Buffer.from(field.authTag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(field.ciphertext, "base64")),
      decipher.final(), // throws if ciphertext/AAD/tag were tampered with
    ]);
    return plaintext.toString("utf8");
  } finally {
    plaintextKey.fill(0);
  }
}

/** Same pattern as encryptField/decryptField but for binary file content. */
export async function encryptBuffer(
  kms: KmsProvider,
  plaintext: Buffer,
  aad: string
): Promise<EncryptedBuffer> {
  const { plaintextKey, encryptedDataKey, keyId, keyVersion } = await kms.generateDataKey();
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", plaintextKey, iv);
    cipher.setAAD(Buffer.from(aad, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext,
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      encryptedDataKey: encryptedDataKey.toString("base64"),
      kmsKeyId: keyId,
      keyVersion,
    };
  } finally {
    plaintextKey.fill(0);
  }
}

export async function decryptBuffer(
  kms: KmsProvider,
  encrypted: {
    ciphertext: Buffer;
    iv: string;
    authTag: string;
    encryptedDataKey: string;
    kmsKeyId: string;
  },
  aad: string
): Promise<Buffer> {
  const plaintextKey = await kms.decryptDataKey(
    Buffer.from(encrypted.encryptedDataKey, "base64"),
    encrypted.kmsKeyId
  );
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      plaintextKey,
      Buffer.from(encrypted.iv, "base64")
    );
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(Buffer.from(encrypted.authTag, "base64"));
    return Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
  } finally {
    plaintextKey.fill(0);
  }
}

import { describe, expect, it } from "vitest";
import crypto from "crypto";
import { LocalKmsProvider } from "../src/crypto/kms";
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

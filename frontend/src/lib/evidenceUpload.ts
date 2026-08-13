import { createClient } from "@supabase/supabase-js";
import { api } from "./api";

interface PresignResponse {
  storageKey: string;
  bucket: string;
  uploadUrl: string;
  uploadToken: string;
  aad: string;
  dek: string; // base64 — plaintext DEK, used once here then discarded
  encryptedDataKey: string;
  kmsKeyId: string;
  keyVersion: number;
}

/**
 * Encrypts a file with WebCrypto AES-256-GCM using the exact same wire
 * format the backend's own encryptBuffer() produces (12-byte random IV,
 * AAD binding, 16-byte GCM tag) — either side can decrypt what the other
 * encrypted. The DEK never leaves this function except as bytes fed
 * straight into SubtleCrypto; nothing here persists it.
 */
async function encryptForUpload(file: File, dekBase64: string, aad: string): Promise<{ ciphertext: ArrayBuffer; iv: string; authTag: string }> {
  const dekBytes = Uint8Array.from(atob(dekBase64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", dekBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = await file.arrayBuffer();

  // WebCrypto's AES-GCM output is ciphertext || tag (tag = last 16 bytes),
  // matching Node's cipher.getAuthTag() length exactly — split it the same
  // way the server would if it had done the encrypting.
  const combined = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
      key,
      plaintext
    )
  );
  // Copied into fresh, plain ArrayBuffers (not Uint8Array.slice/subarray,
  // which TS's DOM lib types as backed by the broader ArrayBufferLike —
  // it's SharedArrayBuffer that Blob's BlobPart type actually rejects, not
  // anything real here) — this is what actually satisfies BlobPart below.
  const ciphertext = combined.slice(0, -16).buffer as ArrayBuffer;
  const tag = combined.slice(-16);

  return {
    ciphertext,
    iv: btoa(String.fromCharCode(...iv)),
    authTag: btoa(String.fromCharCode(...tag)),
  };
}

async function sha256Hex(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Uploads a file's ciphertext directly to object storage, bypassing this
 * app's own backend for the bytes — the only way past Vercel's request-body
 * limit for large evidence files. Returns true if it ran (presigned path
 * available), false if the backend says this storage backend doesn't
 * support it (local dev) — callers should fall back to the regular
 * multipart `api.upload()` route in that case.
 */
export async function uploadEvidenceDirect(findingId: string, file: File): Promise<boolean> {
  // Checked before ever calling presign (which would otherwise mint and
  // discard a real DEK for nothing): missing frontend config is just
  // another reason to fall back, not a hard error the caller has to handle.
  if (!import.meta.env.VITE_SUPABASE_URL || !import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY) {
    return false;
  }

  let presign: PresignResponse;
  try {
    presign = await api.post<PresignResponse>(`/findings/${findingId}/evidence/presign`, {
      originalFilename: file.name,
      mimeType: file.type || "application/octet-stream",
    });
  } catch {
    return false; // 501 (or any failure) — caller falls back to multipart upload
  }

  const [sha256, encrypted] = await Promise.all([sha256Hex(file), encryptForUpload(file, presign.dek, presign.aad)]);

  const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY);
  const { error } = await supabase.storage
    .from(presign.bucket)
    .uploadToSignedUrl(presign.storageKey, presign.uploadToken, new Blob([encrypted.ciphertext]));
  if (error) throw new Error(`Direct upload failed: ${error.message}`);

  await api.post(`/findings/${findingId}/evidence/complete`, {
    storageKey: presign.storageKey,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    encryptedDataKey: presign.encryptedDataKey,
    kmsKeyId: presign.kmsKeyId,
    keyVersion: presign.keyVersion,
    originalFilename: file.name,
    mimeType: file.type || "application/octet-stream",
    sizeBytes: file.size,
    sha256,
  });

  return true;
}

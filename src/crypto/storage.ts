import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

// Swappable object-storage boundary. Production implementations target S3/GCS/
// Azure Blob (with provider-side SSE-KMS enabled as defense-in-depth on top of
// the application-layer encryption already applied before bytes reach here).
export interface ObjectStorage {
  put(key: string, data: Buffer): Promise<void>;
  get(key: string): Promise<Buffer>;
  /**
   * Optional: a short-lived, single-use URL the *browser* can PUT ciphertext
   * to directly, bypassing this server entirely for the file bytes — the
   * only way past Vercel's request-body limit for large evidence files (see
   * README "Presigned evidence uploads"). Providers that can't support this
   * (LocalObjectStorage) simply don't implement it; callers must treat it as
   * optional and fall back to the regular multipart upload route.
   */
  createUploadUrl?(key: string): Promise<{ url: string; token: string }>;
  /** Cheap existence check (no body download) — lets a caller confirm a
   * presigned upload actually landed before trusting client-supplied
   * metadata about it. */
  exists?(key: string): Promise<boolean>;
  /**
   * Permanently removes an object. Only real caller today is the data-erasure
   * flow (src/modules/clients/client-deletion.service.ts) — nothing else in
   * the app deletes files, by design (evidence/reports are meant to be
   * immutable once uploaded). Not marked optional: an ObjectStorage provider
   * that can't actually delete a file can't support real data erasure, and
   * that should be a loud implementation gap, not a silently-skipped step.
   */
  delete(key: string): Promise<void>;
}

/** Local filesystem stand-in for dev/test. Bytes written here are ALREADY
 * ciphertext — encryptBuffer() must run before put(), decryptBuffer() after get(). */
export class LocalObjectStorage implements ObjectStorage {
  constructor(private readonly baseDir: string) {}

  async put(key: string, data: Buffer): Promise<void> {
    const fullPath = this.resolve(key);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, data);
  }

  async get(key: string): Promise<Buffer> {
    return fs.readFile(this.resolve(key));
  }

  async delete(key: string): Promise<void> {
    try {
      await fs.unlink(this.resolve(key));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }

  private resolve(key: string): string {
    const normalized = path.normalize(key).replace(/^(\.\.[/\\])+/, "");
    return path.join(this.baseDir, normalized);
  }
}

export function newStorageKey(prefix: string): string {
  return `${prefix}/${crypto.randomUUID()}`;
}

import { createClient, SupabaseClient } from "@supabase/supabase-js";
import { ObjectStorage } from "../storage";

/**
 * Object storage backed by a private Supabase Storage bucket. Bytes handed to
 * put()/get() are ALREADY AES-256-GCM ciphertext (encryptBuffer() runs before
 * put(), decryptBuffer() runs after get()) — this class never sees plaintext.
 *
 * Uses the service_role key so uploads/downloads bypass the bucket's RLS
 * policies entirely, mirroring how the app's direct Postgres connection
 * bypasses table RLS. That key must never reach a browser or mobile client —
 * it belongs in server-side env only. Get it from the Supabase dashboard
 * (Project Settings -> API -> service_role secret); it cannot be fetched
 * through the Supabase MCP tools by design.
 */
export class SupabaseObjectStorage implements ObjectStorage {
  private readonly client: SupabaseClient;
  private readonly bucket: string;

  constructor(supabaseUrl: string, serviceRoleKey: string, bucket: string) {
    this.client = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    this.bucket = bucket;
  }

  async put(key: string, data: Buffer): Promise<void> {
    const { error } = await this.client.storage.from(this.bucket).upload(key, data, {
      contentType: "application/octet-stream",
      upsert: false,
    });
    if (error) throw new Error(`Supabase storage upload failed for "${key}": ${error.message}`);
  }

  async get(key: string): Promise<Buffer> {
    const { data, error } = await this.client.storage.from(this.bucket).download(key);
    if (error || !data) {
      throw new Error(`Supabase storage download failed for "${key}": ${error?.message ?? "no data"}`);
    }
    return Buffer.from(await data.arrayBuffer());
  }

  async createUploadUrl(key: string): Promise<{ url: string; token: string }> {
    const { data, error } = await this.client.storage.from(this.bucket).createSignedUploadUrl(key);
    if (error || !data) {
      throw new Error(`Supabase createSignedUploadUrl failed for "${key}": ${error?.message ?? "no data"}`);
    }
    return { url: data.signedUrl, token: data.token };
  }

  async exists(key: string): Promise<boolean> {
    const lastSlash = key.lastIndexOf("/");
    const dir = key.slice(0, lastSlash);
    const filename = key.slice(lastSlash + 1);
    const { data, error } = await this.client.storage.from(this.bucket).list(dir, { search: filename });
    if (error) throw new Error(`Supabase storage list failed for "${key}": ${error.message}`);
    return (data ?? []).some((entry) => entry.name === filename);
  }

  async delete(key: string): Promise<void> {
    const { error } = await this.client.storage.from(this.bucket).remove([key]);
    if (error) throw new Error(`Supabase storage delete failed for "${key}": ${error.message}`);
  }
}

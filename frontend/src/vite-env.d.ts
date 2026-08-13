/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  readonly VITE_CLERK_PUBLISHABLE_KEY: string;
  // Public project URL + publishable key (sb_publishable_..., NOT the
  // secret service_role key) — used only to hit a presigned upload URL the
  // backend already scoped with a one-time token; safe to expose
  // client-side by design. See lib/evidenceUpload.ts.
  readonly VITE_SUPABASE_URL?: string;
  readonly VITE_SUPABASE_PUBLISHABLE_KEY?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

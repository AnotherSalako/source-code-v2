// Local dev: unset, so requests hit "/api/..." and the Vite dev proxy
// (vite.config.ts) forwards to localhost:4000. Production (Vercel): set to
// the deployed backend project's URL, e.g. https://jupiter-api.vercel.app —
// there's no dev proxy in a static production build.
const API_BASE = import.meta.env.VITE_API_URL ?? "/api";

// Clerk session tokens are short-lived (~60s) and auto-refreshed — there's
// nothing to persist here the way a long-lived JWT was. lib/auth.tsx sets
// this to Clerk's `getToken` (from useAuth()) once signed in, and back to
// null on sign-out; every request calls it fresh rather than caching a token.
let clerkTokenGetter: (() => Promise<string | null>) | null = null;

export function setClerkTokenGetter(getter: (() => Promise<string | null>) | null): void {
  clerkTokenGetter = getter;
}

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = clerkTokenGetter ? await clerkTokenGetter() : null;
  const headers = new Headers(options.headers);
  if (!(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (!res.ok) {
    let message: unknown = res.statusText;
    let body: unknown;
    try {
      body = await res.json();
      const errorValue = (body as { error?: unknown }).error;
      if (typeof errorValue === "string") {
        message = errorValue;
      } else if (errorValue && typeof errorValue === "object" && "formErrors" in errorValue) {
        message = (errorValue as { formErrors?: string[] }).formErrors?.join(", ") ?? message;
      }
    } catch {
      // response had no JSON body
    }
    throw new ApiError(typeof message === "string" ? message : JSON.stringify(message), res.status, body);
  }

  if (res.status === 204) return undefined as T;
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) return res.json() as Promise<T>;
  return res.blob() as unknown as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "DELETE", body: body ? JSON.stringify(body) : undefined }),
  upload: <T>(path: string, file: File, fields?: Record<string, string>) => {
    const form = new FormData();
    form.append("file", file);
    for (const [key, value] of Object.entries(fields ?? {})) form.append(key, value);
    return request<T>(path, { method: "POST", body: form });
  },
  downloadBlob: async (path: string): Promise<Blob> => request<Blob>(path),
};

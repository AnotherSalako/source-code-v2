import { randomBytes } from "crypto";
import dns from "dns/promises";

export const VERIFICATION_TOKEN_PREFIX = "enforcer-verify";
export const WELL_KNOWN_PATH = "/.well-known/enforcer-verification.txt";

export function generateVerificationToken(): string {
  return `${VERIFICATION_TOKEN_PREFIX}=${randomBytes(16).toString("hex")}`;
}

/** DNS TXT record on the bare hostname must contain the exact token string. */
export async function checkDnsTxt(hostname: string, token: string): Promise<boolean> {
  let records: string[][];
  try {
    records = await dns.resolveTxt(hostname);
  } catch {
    return false; // NXDOMAIN, no TXT records, timeout — all just "not verified yet"
  }
  return records.some((chunks) => chunks.join("").trim() === token);
}

/**
 * `http(s)://<host>/.well-known/enforcer-verification.txt` must return the
 * token as its exact (trimmed) body. A short timeout and a hard byte cap
 * keep this from ever being used as a slow-loris or arbitrary-download
 * vector against whatever the client points us at.
 */
export async function checkHttpFile(baseUrl: string, token: string): Promise<boolean> {
  const target = new URL(WELL_KNOWN_PATH, baseUrl).toString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch(target, { signal: controller.signal, redirect: "follow" });
    if (!res.ok) return false;
    const reader = res.body?.getReader();
    if (!reader) return (await res.text()).trim() === token;
    let bytes = 0;
    let text = "";
    const decoder = new TextDecoder();
    while (bytes < 4096) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      text += decoder.decode(value, { stream: true });
    }
    await reader.cancel().catch(() => {});
    return text.trim() === token;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

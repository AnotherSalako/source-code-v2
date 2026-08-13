import { env } from "../config/env";

const BASE = "https://www.virustotal.com/api/v3";

export interface ReputationResult {
  malicious: number;
  suspicious: number;
  totalEngines: number;
  permalink?: string;
}

function headers(): Record<string, string> {
  return { "x-apikey": env.virusTotalApiKey! };
}

/**
 * Looks up a file's SHA-256 against VirusTotal's existing corpus. Returns
 * `null` when VT has never seen the hash (a 404 here means "no data", NOT
 * "confirmed clean" — callers must not conflate the two) or the feature
 * isn't configured.
 */
export async function lookupFileHash(sha256: string): Promise<ReputationResult | null> {
  if (!env.virusTotalApiKey) return null;
  const res = await fetch(`${BASE}/files/${sha256}`, { headers: headers() });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`VirusTotal file lookup failed: ${res.status}`);
  const json = (await res.json()) as {
    data: { attributes: { last_analysis_stats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number } } };
  };
  const stats = json.data.attributes.last_analysis_stats;
  return {
    malicious: stats.malicious,
    suspicious: stats.suspicious,
    totalEngines: stats.malicious + stats.suspicious + stats.harmless + stats.undetected + stats.timeout,
    permalink: `https://www.virustotal.com/gui/file/${sha256}`,
  };
}

function urlToId(url: string): string {
  // VT's URL identifier is the URL's bytes, base64url-encoded, padding stripped.
  return Buffer.from(url, "utf8").toString("base64url").replace(/=+$/, "");
}

async function fetchAnalysisStats(analysisId: string): Promise<{ stats: ReputationResult; completed: boolean } | null> {
  const res = await fetch(`${BASE}/analyses/${analysisId}`, { headers: headers() });
  if (!res.ok) return null;
  const json = (await res.json()) as {
    data: { attributes: { status: string; stats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number } } };
  };
  const attrs = json.data.attributes;
  const s = attrs.stats;
  return {
    completed: attrs.status === "completed",
    stats: {
      malicious: s.malicious,
      suspicious: s.suspicious,
      totalEngines: s.malicious + s.suspicious + s.harmless + s.undetected + s.timeout,
    },
  };
}

/**
 * Looks up a URL/domain's reputation. If VT already has an analysis, uses it
 * directly; otherwise submits it and polls briefly (VT URL analysis is
 * normally fast). Returns `null` — "no verdict available" — rather than
 * blocking a scan job indefinitely if VT doesn't finish in that window.
 */
export async function lookupUrl(url: string): Promise<ReputationResult | null> {
  if (!env.virusTotalApiKey) return null;

  const id = urlToId(url);
  const existing = await fetch(`${BASE}/urls/${id}`, { headers: headers() });
  if (existing.ok) {
    const json = (await existing.json()) as {
      data: { attributes: { last_analysis_stats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number } } };
    };
    const s = json.data.attributes.last_analysis_stats;
    return {
      malicious: s.malicious,
      suspicious: s.suspicious,
      totalEngines: s.malicious + s.suspicious + s.harmless + s.undetected + s.timeout,
      permalink: `https://www.virustotal.com/gui/url/${id}`,
    };
  }
  if (existing.status !== 404) throw new Error(`VirusTotal URL lookup failed: ${existing.status}`);

  const submit = await fetch(`${BASE}/urls`, {
    method: "POST",
    headers: { ...headers(), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url }),
  });
  if (!submit.ok) throw new Error(`VirusTotal URL submission failed: ${submit.status}`);
  const submitJson = (await submit.json()) as { data: { id: string } };

  for (let attempt = 0; attempt < 4; attempt++) {
    await new Promise((r) => setTimeout(r, 3000));
    const result = await fetchAnalysisStats(submitJson.data.id);
    if (result?.completed) return { ...result.stats, permalink: `https://www.virustotal.com/gui/url/${id}` };
  }
  return null; // still queued after a reasonable wait — treat as no verdict rather than stalling the caller
}

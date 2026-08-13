import { logger } from "../../config/logger";
import { SbomDependency } from "./sbom-parser";

// OSV.dev (https://osv.dev) — Google-run, free, no API key, no rate-limit
// auth required for reasonable batch sizes. Real, live vulnerability data
// (GitHub Security Advisories, npm advisories, and more), not a mock or a
// hand-maintained list this app would have to keep current itself.
const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const REQUEST_TIMEOUT_MS = 20_000;
const BATCH_CHUNK_SIZE = 100; // OSV's own documented batch endpoint guidance — chunk rather than send one huge request
const MAX_VULN_DETAIL_FETCHES = 200; // bounds the second-pass detail lookups if a scan turns up an unusually large number of hits

export interface SbomIssue {
  dependency: string;
  version: string;
  vulnerabilityId: string;
  aliases: string[];
  summary: string;
  severity: string | null; // OSV's database_specific.severity when present — not every advisory carries one, honestly reported as null rather than guessed
}

async function postJson(url: string, body: unknown): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      logger.warn({ status: res.status, url }, "OSV.dev request failed");
      return null;
    }
    return await res.json();
  } catch (err) {
    logger.warn({ err, url }, "OSV.dev request errored");
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function getJson(url: string): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) {
      logger.warn({ status: res.status, url }, "OSV.dev request failed");
      return null;
    }
    return await res.json();
  } catch (err) {
    logger.warn({ err, url }, "OSV.dev request errored");
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Two-pass lookup: the batch endpoint is cheap but only returns
 * vulnerability IDs (by design — full records would make a large batch
 * response huge), so a second pass fetches full details (summary,
 * severity, aliases) for whatever IDs came back. Never throws — a failed
 * OSV request degrades to "no issues found for this chunk" rather than
 * failing the whole scan, same graceful-degradation precedent as every
 * other external call in this app (VirusTotal, Nmap, crt.sh).
 */
export async function findVulnerabilities(deps: SbomDependency[]): Promise<SbomIssue[]> {
  const issues: SbomIssue[] = [];
  const detailCache = new Map<string, any>();

  for (const batch of chunk(deps, BATCH_CHUNK_SIZE)) {
    const body = {
      queries: batch.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })),
    };
    const result = await postJson(OSV_BATCH_URL, body);
    if (!result?.results) continue;

    for (let i = 0; i < batch.length; i++) {
      const dep = batch[i];
      const vulnRefs = result.results[i]?.vulns ?? [];

      for (const ref of vulnRefs) {
        if (!ref.id) continue;

        if (!detailCache.has(ref.id) && detailCache.size < MAX_VULN_DETAIL_FETCHES) {
          detailCache.set(ref.id, await getJson(`${OSV_VULN_URL}/${encodeURIComponent(ref.id)}`));
        }
        const detail = detailCache.get(ref.id);

        issues.push({
          dependency: dep.name,
          version: dep.version,
          vulnerabilityId: ref.id,
          aliases: Array.isArray(detail?.aliases) ? detail.aliases : [],
          summary: typeof detail?.summary === "string" ? detail.summary : `Known vulnerability ${ref.id}`,
          severity: typeof detail?.database_specific?.severity === "string" ? detail.database_specific.severity : null,
        });
      }
    }
  }

  return issues;
}

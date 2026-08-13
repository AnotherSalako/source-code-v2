import dns from "dns/promises";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { logger } from "../../config/logger";
import { isPrivateAddress } from "../scanning/scan-runner";
import { scanPorts } from "./nmap";

// Deliberately passive/non-intrusive, same posture as the Nuclei tag set in
// scan-runner.ts: certificate-transparency logs surface subdomain
// candidates (no request ever reaches the target for that part), and
// nothing more aggressive than an Nmap service/version check (-sV, no
// scripts, no OS fingerprinting — see nmap.ts) runs against whatever
// currently resolves publicly, against a handful of well-known ports — no
// hostname brute forcing, no exploitation. Anything past that is a manual
// pentest activity, same line scan-runner.ts already draws. Results never
// become scannable Assets on their own — they land as DiscoveredAsset rows
// a human reviews and promotes (see discovery.routes.ts).
const CT_LOOKUP_TIMEOUT_MS = 15_000;
const MAX_RUNTIME_MS = 3 * 60 * 1000;
const MAX_CANDIDATES = 50; // crt.sh can return thousands of historical certs for a big domain; cap what one run processes
const COMMON_PORTS = [21, 22, 25, 80, 443, 3389, 8080, 8443];

function stripWildcard(host: string): string {
  return host.replace(/^\*\./, "").trim().toLowerCase();
}

function bareHostname(identifier: string): string {
  return identifier.includes("://") ? new URL(identifier).hostname : identifier.split("/")[0];
}

async function queryCertTransparency(domain: string): Promise<string[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CT_LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: controller.signal });
    if (!res.ok) return [];
    const rows = (await res.json()) as { name_value?: string }[];
    const names = new Set<string>();
    for (const row of rows) {
      for (const raw of (row.name_value ?? "").split("\n")) {
        const host = stripWildcard(raw);
        if (host && host !== domain && host.endsWith(`.${domain}`) && !host.includes(" ")) names.add(host);
      }
    }
    return [...names];
  } catch (err) {
    logger.warn({ err, domain }, "Certificate-transparency lookup failed — continuing with an empty candidate set");
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

/** Returns the resolved address, or null if the hostname no longer resolves — stale CT entries are dropped, not reported. */
async function resolveLive(hostname: string): Promise<string | null> {
  try {
    const { address } = await dns.lookup(hostname);
    return address;
  } catch {
    return null;
  }
}

export async function startDiscovery(params: {
  engagementId: string;
  assetId: string;
  triggeredById: string;
}): Promise<{ discoveryJobId: string }> {
  const job = await prisma.discoveryJob.create({
    data: {
      engagementId: params.engagementId,
      assetId: params.assetId,
      status: "QUEUED",
      triggeredById: params.triggeredById,
    },
  });

  // Fire and forget, same reasoning as startScan in scan-runner.ts: the
  // caller polls GET .../discovery-jobs/:id rather than waiting on this
  // request, and this process must stay alive for the run's duration.
  void runDiscoveryJob(job.id);

  return { discoveryJobId: job.id };
}

/** Runs one discovery job end to end. Never throws — every failure mode ends in a FAILED job with errorMessage set. */
export async function runDiscoveryJob(discoveryJobId: string): Promise<void> {
  const job = await prisma.discoveryJob.findUniqueOrThrow({
    where: { id: discoveryJobId },
    include: { asset: true, engagement: { select: { clientId: true } } },
  });

  try {
    await prisma.discoveryJob.update({ where: { id: discoveryJobId }, data: { status: "RUNNING", startedAt: new Date() } });

    const scopedKms = await tenantKms(job.engagement.clientId);
    const identifier = await decryptField(kms, job.asset.identifierEnc as any, `asset:identifier`);
    const rootDomain = bareHostname(identifier);

    const candidates = (await queryCertTransparency(rootDomain)).slice(0, MAX_CANDIDATES);

    // Dedup against everything already discovered under this asset — a
    // re-run shouldn't re-surface the same subdomain as a fresh NEW row
    // every time. Ciphertext can't be compared directly, so this decrypts
    // and compares in application code, same approach import.service.ts
    // uses for finding dedup.
    const existingRows = await prisma.discoveredAsset.findMany({
      where: { parentAssetId: job.assetId },
      select: { valueEnc: true },
    });
    const existingValues = new Set(
      await Promise.all(existingRows.map((row) => decryptField(kms, row.valueEnc as any, `discoveredAsset:value`)))
    );

    const deadline = Date.now() + MAX_RUNTIME_MS;
    let discoveredCount = 0;

    for (const hostname of candidates) {
      if (Date.now() > deadline) break; // leave the rest for the next run rather than running unbounded
      if (existingValues.has(hostname)) continue;

      const address = await resolveLive(hostname);
      if (!address) continue; // no longer resolves — not part of the live attack surface today

      const portDetails = isPrivateAddress(address) ? [] : await scanPorts(hostname, COMMON_PORTS);
      const openPorts = portDetails.map((p) => p.port);

      await prisma.discoveredAsset.create({
        data: {
          engagementId: job.engagementId,
          parentAssetId: job.assetId,
          discoveryJobId: job.id,
          valueEnc: (await encryptField(scopedKms, hostname, `discoveredAsset:value`)) as any,
          source: "crt.sh",
          openPorts,
          portDetails: portDetails.length > 0 ? (portDetails as any) : undefined,
        },
      });
      discoveredCount++;
    }

    await prisma.discoveryJob.update({
      where: { id: discoveryJobId },
      data: { status: "COMPLETE", completedAt: new Date(), discoveredCount },
    });
  } catch (err) {
    logger.error({ err, discoveryJobId }, "Discovery job failed");
    await prisma.discoveryJob.update({
      where: { id: discoveryJobId },
      data: { status: "FAILED", completedAt: new Date(), errorMessage: err instanceof Error ? err.message : String(err) },
    });
  }
}

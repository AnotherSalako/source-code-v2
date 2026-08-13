import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { tenantKms } from "../../crypto/tenant";
import { logger } from "../../config/logger";
import { isPrivateAddress } from "../scanning/scan-runner";
import { scanPorts, NmapPortResult } from "./nmap";
import { queryCertTransparency, resolveLive, bareHostname, MAX_CANDIDATES, MAX_RUNTIME_MS, COMMON_PORTS } from "./discovery-runner";

// Ordinary discovery (discovery-runner.ts) deliberately never revisits a
// hostname it's already seen — a re-run just dedups and skips. That's
// correct for "hunt for new subdomains" but means nothing today ever
// notices that an *already-known* asset's attack surface changed. Watch
// mode is that missing half: same subdomain hunt (reused, not duplicated),
// plus a second pass that re-scans every already-known, non-IGNORED
// DiscoveredAsset under this root and diffs the result against what's
// stored.
//
// Deliberately NOT folded into runDiscoveryJob() itself — that function's
// entire dedup step exists to avoid rework, which is exactly the behavior
// a watch cycle needs to override for known assets while keeping unchanged
// for genuinely-new ones. Two functions sharing helpers is clearer than one
// function with a mode flag threading through every step.

export function portsEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort((x, y) => x - y);
  const sortedB = [...b].sort((x, y) => x - y);
  return sortedA.every((v, i) => v === sortedB[i]);
}

function serviceKey(p: NmapPortResult): string {
  return `${p.port}/${p.protocol}`;
}

/** Compares old vs new port/service results for one host, returning what changed. Never mutates anything — pure diff. Exported for direct unit testing (no DB/network needed). */
export function diffPorts(
  previous: NmapPortResult[] | null,
  current: NmapPortResult[]
): { kind: "PORT_OPENED" | "PORT_CLOSED" | "SERVICE_CHANGED"; summary: string; details: { before: unknown; after: unknown } }[] {
  const prev = previous ?? [];
  const prevByKey = new Map(prev.map((p) => [serviceKey(p), p]));
  const currByKey = new Map(current.map((p) => [serviceKey(p), p]));
  const changes: ReturnType<typeof diffPorts> = [];

  for (const [key, curr] of currByKey) {
    const before = prevByKey.get(key);
    if (!before) {
      changes.push({
        kind: "PORT_OPENED",
        summary: `Port ${key} opened${curr.service ? ` (${curr.service})` : ""}`,
        details: { before: null, after: curr },
      });
    } else if (before.service !== curr.service || before.version !== curr.version) {
      changes.push({
        kind: "SERVICE_CHANGED",
        summary: `Port ${key} service/version changed`,
        details: { before, after: curr },
      });
    }
  }
  for (const [key, prevEntry] of prevByKey) {
    if (!currByKey.has(key)) {
      changes.push({
        kind: "PORT_CLOSED",
        summary: `Port ${key} closed${prevEntry.service ? ` (was ${prevEntry.service})` : ""}`,
        details: { before: prevEntry, after: null },
      });
    }
  }
  return changes;
}

/**
 * Creates a QUEUED watch job and returns immediately — same shape as
 * startDiscovery()/runDiscoveryJob() in discovery-runner.ts, and for the
 * same reason: the actual cycle can run close to MAX_RUNTIME_MS, and a
 * caller (a human triggering it, or the scheduled-watch cron sweeping
 * several assets in one invocation) must not block on that inline, or a
 * serverless function's own timeout becomes the real limit instead of
 * MAX_RUNTIME_MS. Callers poll GET .../discovery-jobs the same way they
 * already do for ordinary discovery.
 */
export function startWatchCycle(params: { engagementId: string; assetId: string; triggeredById: string }): Promise<{ discoveryJobId: string }> {
  return prisma.discoveryJob
    .create({
      data: {
        engagementId: params.engagementId,
        assetId: params.assetId,
        tool: "watch",
        status: "QUEUED",
        triggeredById: params.triggeredById,
      },
    })
    .then((job) => {
      void runWatchCycleJob(job.id, params.engagementId, params.assetId); // fire-and-forget, mirrors runDiscoveryJob
      return { discoveryJobId: job.id };
    });
}

/** Does the actual work for a watch cycle. Never throws — every failure ends in a FAILED job with errorMessage set, not an unhandled rejection. */
async function runWatchCycleJob(discoveryJobId: string, engagementId: string, assetId: string): Promise<void> {
  try {
    await prisma.discoveryJob.update({ where: { id: discoveryJobId }, data: { status: "RUNNING", startedAt: new Date() } });

    const asset = await prisma.asset.findUniqueOrThrow({
      where: { id: assetId },
      include: { engagement: { select: { clientId: true } } },
    });
    const scopedKms = await tenantKms(asset.engagement.clientId);
    const deadline = Date.now() + MAX_RUNTIME_MS;
    let alertCount = 0;

    // --- Pass 1: re-check known, non-IGNORED assets for drift ---
    const known = await prisma.discoveredAsset.findMany({
      where: { parentAssetId: assetId, status: { not: "IGNORED" } },
    });

    for (const row of known) {
      if (Date.now() > deadline) break;

      const hostname = await decryptField(kms, row.valueEnc as any, `discoveredAsset:value`);
      const address = await resolveLive(hostname);
      if (!address) continue; // no longer resolves — not part of the live surface today; leave the last-known state as-is rather than guessing it's "closed"

      const freshPorts = isPrivateAddress(address) ? [] : await scanPorts(hostname, COMMON_PORTS);
      const previousPorts = (row.portDetails as unknown as NmapPortResult[] | null) ?? null;

      if (!portsEqual(row.openPorts, freshPorts.map((p) => p.port))) {
        const changes = diffPorts(previousPorts, freshPorts);
        for (const change of changes) {
          await prisma.watchAlert.create({
            data: {
              engagementId,
              discoveredAssetId: row.id,
              discoveryJobId,
              kind: change.kind,
              summary: change.summary,
              details: change.details as any,
            },
          });
          alertCount++;
        }
      }

      await prisma.discoveredAsset.update({
        where: { id: row.id },
        data: {
          openPorts: freshPorts.map((p) => p.port),
          // null, not undefined — this is an update, where Prisma treats an
          // undefined field as "leave whatever's already stored," not "set
          // to null." Discovered live: an asset going from some ports to
          // zero ports left the previous scan's stale portDetails in place
          // instead of clearing it, because undefined here silently no-ops
          // on update (it only means "store null" on create, which is a
          // different call with different semantics for the same value).
          portDetails: freshPorts.length > 0 ? (freshPorts as any) : null,
          lastScannedAt: new Date(),
        },
      });
    }

    // --- Pass 2: hunt for brand new subdomains, same as ordinary discovery ---
    const identifier = await decryptField(kms, asset.identifierEnc as any, `asset:identifier`);
    const rootDomain = bareHostname(identifier);
    const candidates = (await queryCertTransparency(rootDomain)).slice(0, MAX_CANDIDATES);

    const existingValues = new Set(
      await Promise.all(
        (await prisma.discoveredAsset.findMany({ where: { parentAssetId: assetId }, select: { valueEnc: true } })).map((r) =>
          decryptField(kms, r.valueEnc as any, `discoveredAsset:value`)
        )
      )
    );

    for (const hostname of candidates) {
      if (Date.now() > deadline) break;
      if (existingValues.has(hostname)) continue;

      const address = await resolveLive(hostname);
      if (!address) continue;

      const portDetails = isPrivateAddress(address) ? [] : await scanPorts(hostname, COMMON_PORTS);

      const newRow = await prisma.discoveredAsset.create({
        data: {
          engagementId,
          parentAssetId: assetId,
          discoveryJobId,
          valueEnc: (await encryptField(scopedKms, hostname, `discoveredAsset:value`)) as any,
          source: "crt.sh",
          openPorts: portDetails.map((p) => p.port),
          portDetails: portDetails.length > 0 ? (portDetails as any) : undefined,
          lastScannedAt: new Date(),
        },
      });

      await prisma.watchAlert.create({
        data: {
          engagementId,
          discoveredAssetId: newRow.id,
          discoveryJobId,
          kind: "NEW_SUBDOMAIN",
          summary: "New subdomain discovered",
          details: { before: null, after: { hostname, openPorts: newRow.openPorts } } as any,
        },
      });
      alertCount++;
    }

    await prisma.discoveryJob.update({
      where: { id: discoveryJobId },
      data: { status: "COMPLETE", completedAt: new Date(), discoveredCount: alertCount },
    });
  } catch (err) {
    logger.error({ err, discoveryJobId }, "Watch cycle failed");
    await prisma.discoveryJob.update({
      where: { id: discoveryJobId },
      data: { status: "FAILED", completedAt: new Date(), errorMessage: err instanceof Error ? err.message : String(err) },
    });
  }
}

import { spawn } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import dns from "dns/promises";
import { prisma } from "../../db/prisma";
import { kms } from "../../crypto";
import { decryptField, encryptField } from "../../crypto/envelope";
import { env } from "../../config/env";
import { logger } from "../../config/logger";
import { importScanItems } from "../findings/import.service";
import { checkUrlReputation } from "../../integrations/malware-check";

// Deliberately non-intrusive: header/config/exposure checks only, no
// fuzzing, brute-force, or exploit templates. This is what "automated,
// unattended, safe by default" scanning means here — anything more
// aggressive is a manual pentest activity (POST .../findings, by hand),
// not something a client can trigger against their own production site
// without a human in the loop.
const SAFE_NUCLEI_TAGS = "cors,exposure,misconfig,tech,generic,headers";
const MAX_RUNTIME_MS = 5 * 60 * 1000;
// This tag set clusters down to several thousand requests against a single
// host (verified live: ~3.5 minutes end to end at 30 req/s). 60 req/s is
// still a gentle, no-burst rate against one host — real DAST tools go far
// higher — and roughly halves that without changing what's being sent.
const REQUEST_RATE_LIMIT = "60"; // requests/sec, passed to nuclei -rl

function isPrivateAddress(ip: string): boolean {
  if (ip === "127.0.0.1" || ip === "::1") return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (/^169\.254\./.test(ip)) return true; // link-local, also the cloud metadata address
  if (/^f[cd][0-9a-f]{0,2}:/i.test(ip)) return true; // fc00::/7 unique local
  if (/^fe80:/i.test(ip)) return true; // link-local v6
  return false;
}

async function assertPubliclyRoutable(hostname: string): Promise<void> {
  if (env.allowInternalScanTargets) return;
  const addresses = await dns.lookup(hostname, { all: true });
  const bad = addresses.find(({ address }) => isPrivateAddress(address));
  if (bad) {
    throw new Error(
      `${hostname} resolves to a private/internal address (${bad.address}) — automated scans only target public hosts. Set ALLOW_INTERNAL_SCAN_TARGETS=true to lift this for local/dev use.`
    );
  }
}

function runNuclei(targetUrl: string, outFile: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = [
      "-u", targetUrl,
      "-jsonl", "-o", outFile,
      "-silent",
      "-tags", SAFE_NUCLEI_TAGS,
      "-rl", REQUEST_RATE_LIMIT,
      "-timeout", "10",
      // Without this, Nuclei phones home to check for a template update on
      // every single run — an unattended, on-demand scan endpoint shouldn't
      // have its latency (or its ability to run at all) depend on GitHub's
      // availability. Keep templates current out of band (`nuclei -update-templates`).
      "-duc",
    ];
    // stdio all "ignore": results come from the -o file, not stdout, and an
    // unread stdout/stderr pipe fills its OS buffer and blocks the child
    // process forever once Nuclei writes enough to it — this is not
    // hypothetical, it's what actually hung the first version of this code.
    const child = spawn(env.nucleiBinPath, args, { windowsHide: true, stdio: ["ignore", "ignore", "ignore"] });

    const killTimer = setTimeout(() => {
      child.kill();
      reject(new Error(`Scan exceeded the ${MAX_RUNTIME_MS / 1000}s runtime cap and was terminated`));
    }, MAX_RUNTIME_MS);

    child.on("error", (err) => {
      clearTimeout(killTimer);
      // ENOENT here almost always means the nuclei binary isn't on PATH —
      // surface that plainly rather than a raw spawn error.
      reject(
        (err as NodeJS.ErrnoException).code === "ENOENT"
          ? new Error(`Could not run "${env.nucleiBinPath}" — is Nuclei installed and on PATH? Set NUCLEI_BIN_PATH otherwise.`)
          : err
      );
    });
    child.on("close", () => {
      clearTimeout(killTimer);
      resolve(); // a non-zero exit from nuclei itself isn't fatal — the output file (possibly empty) is what we act on
    });
  });
}

/**
 * Runs one scan job end to end: resolve + safety-check the target, spawn
 * Nuclei, import whatever it found through the same dedup path manual
 * imports use, and record the outcome on the ScanJob row. Never throws —
 * every failure mode (bad target, missing binary, timeout, crash) ends in
 * a FAILED job with errorMessage set, so the caller can fire this and move
 * on without a try/catch of its own.
 */
/**
 * Creates the Test + ScanJob rows and fires runScanJob in the background —
 * shared by the manual trigger (POST .../assets/:id/scan) and the scheduled
 * cron sweep (GET /internal/scheduled-scans), so a scan started either way
 * behaves identically. Caller is responsible for every precondition check
 * (authorization, verification, scope, asset type, no scan already running)
 * — this just does the mechanical part.
 */
export async function startScan(params: {
  engagementId: string;
  assetId: string;
  methodology: string;
  triggeredById: string;
}): Promise<{ scanJobId: string; testId: string }> {
  const test = await prisma.test.create({
    data: {
      engagementId: params.engagementId,
      assetId: params.assetId,
      type: "VULN_SCAN",
      methodology: params.methodology,
      toolUsed: "Nuclei",
      testerId: params.triggeredById,
      status: "IN_PROGRESS",
      startedAt: new Date(),
    },
  });

  const scanJob = await prisma.scanJob.create({
    data: {
      engagementId: params.engagementId,
      assetId: params.assetId,
      testId: test.id,
      tool: "nuclei",
      status: "QUEUED",
      triggeredById: params.triggeredById,
    },
  });

  // Fire and forget: this process must stay alive for the scan's duration
  // to complete it (see README "Website scanning" — not deployable on
  // Vercel's serverless runtime for this reason). Callers poll GET
  // /scan-jobs/:id rather than waiting on the triggering request.
  void runScanJob(scanJob.id).then(async () => {
    await prisma.test.update({ where: { id: test.id }, data: { status: "COMPLETE", completedAt: new Date() } });
  });

  return { scanJobId: scanJob.id, testId: test.id };
}

export async function runScanJob(scanJobId: string): Promise<void> {
  const job = await prisma.scanJob.findUniqueOrThrow({ where: { id: scanJobId }, include: { asset: true } });

  try {
    const targetUrl = await decryptField(kms, job.asset.identifierEnc as any, `asset:identifier`);
    const url = new URL(targetUrl.includes("://") ? targetUrl : `https://${targetUrl}`);
    await assertPubliclyRoutable(url.hostname);

    await prisma.scanJob.update({ where: { id: scanJobId }, data: { status: "RUNNING", startedAt: new Date() } });

    const outFile = path.join(os.tmpdir(), `enforcer-scan-${scanJobId}.jsonl`);
    await runNuclei(url.toString(), outFile);

    const raw = await fs.readFile(outFile, "utf8").catch(() => "");
    await fs.unlink(outFile).catch(() => {});
    const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
    const items = lines.map((l) => JSON.parse(l) as Record<string, unknown>);

    const outcome = await importScanItems({
      engagementId: job.engagementId,
      testId: job.testId!,
      format: "nuclei",
      items,
      forceAssetId: job.assetId, // already know the asset — skip identifier re-matching entirely
    });

    // Domain/URL reputation check (VirusTotal) — separate from the Nuclei
    // template set entirely, so it's skipped cleanly (not a failure) when
    // VIRUSTOTAL_API_KEY isn't configured. Only ever adds at most one extra
    // finding item, merged into the same job's counts.
    let reputationCreated = 0;
    let reputationSkipped = 0;
    if (env.virusTotalApiKey) {
      try {
        const reputationItem = await checkUrlReputation(url.toString());
        if (reputationItem) {
          const reputationOutcome = await importScanItems({
            engagementId: job.engagementId,
            testId: job.testId!,
            format: "normalized",
            items: [reputationItem as unknown as Record<string, unknown>],
            forceAssetId: job.assetId,
          });
          reputationCreated = reputationOutcome.createdIds.length;
          reputationSkipped = reputationOutcome.skipped.length;
        }
      } catch (err) {
        logger.error({ err, scanJobId }, "URL reputation check failed — continuing without it");
      }
    }

    await prisma.scanJob.update({
      where: { id: scanJobId },
      data: {
        status: "COMPLETE",
        completedAt: new Date(),
        findingsCreated: outcome.createdIds.length + reputationCreated,
        findingsSkipped: outcome.skipped.length + reputationSkipped,
        rawResultEnc: raw ? ((await encryptField(kms, raw, `scanjob:rawResult`)) as any) : undefined,
      },
    });
  } catch (err) {
    logger.error({ err, scanJobId }, "Scan job failed");
    await prisma.scanJob.update({
      where: { id: scanJobId },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage: err instanceof Error ? err.message : String(err),
      },
    });
  }
}

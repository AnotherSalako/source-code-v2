import { spawn } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { env } from "../../config/env";
import { logger } from "../../config/logger";

// Same "safe by default" posture as scan-runner.ts's Nuclei integration:
// service/version detection only (-sV), no OS fingerprinting, no NSE
// scripts (--script), no aggressive mode (-A). Anything past "what service
// is listening and what version does it report" is a manual pentest
// activity, not something to run unattended just because a client owns
// the asset — same line the rest of this codebase already draws.
const MAX_RUNTIME_MS = 3 * 60 * 1000;

export interface NmapPortResult {
  port: number;
  protocol: string;
  service: string | null;
  version: string | null;
}

function runNmap(host: string, ports: number[], outFile: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = [
      "-sV", // service/version detection — the entire point of using nmap over a bare connect check
      "-Pn", // skip host-discovery ping — discovery-runner.ts already confirmed this host resolves
      "-T4", // reasonably fast; not the stealth-evading slow end of nmap's timing templates
      "-p",
      ports.join(","),
      "-oG",
      outFile, // grepable output — a stable, line-based format meant for exactly this, unlike XML which would need a real parser dependency
      host,
    ];
    // stdio all "ignore", same reasoning as scan-runner.ts's Nuclei spawn:
    // results come from the -oG file, not stdout, and an unread stdout/
    // stderr pipe can fill its OS buffer and block the child process
    // forever once it writes enough to it.
    const child = spawn(env.nmapBinPath, args, { windowsHide: true, stdio: ["ignore", "ignore", "ignore"] });

    const killTimer = setTimeout(() => {
      child.kill();
      reject(new Error(`Nmap scan exceeded the ${MAX_RUNTIME_MS / 1000}s runtime cap and was terminated`));
    }, MAX_RUNTIME_MS);

    child.on("error", (err) => {
      clearTimeout(killTimer);
      reject(
        (err as NodeJS.ErrnoException).code === "ENOENT"
          ? new Error(`Could not run "${env.nmapBinPath}" — is Nmap installed and on PATH? Set NMAP_BIN_PATH otherwise.`)
          : err
      );
    });
    child.on("close", () => {
      clearTimeout(killTimer);
      resolve(); // a non-zero exit from nmap itself isn't fatal — the output file (possibly empty) is what we act on
    });
  });
}

/**
 * Parses Nmap's grepable (-oG) output. Format per open-ports line:
 *   Host: <ip> (<hostname>)\tPorts: <port>/<state>/<proto>/<owner>/<service>/<rpc>/<version>/, ...
 * Documented and unchanged for well over a decade — see
 * https://nmap.org/book/output-formats-grepable-output.html for the field
 * layout this relies on. Nmap escapes a literal "/" inside a field (common
 * in version strings, e.g. "Apache/2.4.41") as "\/" specifically so the
 * field separator stays unambiguous — split on unescaped "/" only, then
 * unescape, or a version string containing a slash silently corrupts every
 * field after it.
 */
export function parseGrepableOutput(raw: string): NmapPortResult[] {
  const results: NmapPortResult[] = [];

  for (const line of raw.split("\n")) {
    if (!line.startsWith("Host:") || !line.includes("Ports:")) continue;

    const afterPorts = line.split("Ports:")[1];
    if (!afterPorts) continue;
    // Everything up to the next tab-delimited field ("Ignored State:",
    // "OS:", etc., if present) is the port list.
    const portsSection = afterPorts.split(/\t[A-Z]/)[0];

    for (const entry of portsSection.split(", ")) {
      const fields = entry
        .trim()
        .split(/(?<!\\)\//)
        .map((f) => f.replace(/\\\//g, "/"));
      if (fields.length < 7) continue;
      const [portStr, state, protocol, , service, , version] = fields;
      if (state !== "open") continue;
      const port = Number(portStr);
      if (!Number.isFinite(port)) continue;
      results.push({
        port,
        protocol: protocol || "tcp",
        service: service?.trim() || null,
        version: version?.trim() || null,
      });
    }
  }

  return results;
}

/**
 * Service/version-fingerprint check against a fixed, small port list —
 * never a full port sweep. Returns [] (not a thrown error) on any failure
 * — binary missing, timeout, target unreachable — so a discovery run
 * treats "nmap didn't work this time" the same as "nothing open", rather
 * than losing an otherwise-successfully-discovered asset over one
 * enrichment step failing. Same graceful-degradation precedent as the
 * VirusTotal reputation check in scan-runner.ts.
 */
export async function scanPorts(host: string, ports: number[]): Promise<NmapPortResult[]> {
  const outFile = path.join(os.tmpdir(), `jupiter-nmap-${Date.now()}-${Math.random().toString(36).slice(2)}.gnmap`);
  try {
    await runNmap(host, ports, outFile);
    const raw = await fs.readFile(outFile, "utf8").catch(() => "");
    return parseGrepableOutput(raw);
  } catch (err) {
    logger.warn({ err, host }, "Nmap port scan failed — continuing without service/version detail");
    return [];
  } finally {
    await fs.unlink(outFile).catch(() => {});
  }
}

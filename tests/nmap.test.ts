import { describe, expect, it } from "vitest";
import { parseGrepableOutput } from "../src/modules/discovery/nmap";

// Sample lines shaped exactly like real Nmap -oG output — see
// https://nmap.org/book/output-formats-grepable-output.html. Hand-crafted
// rather than captured from a live run (no Nmap binary was available while
// building this — see agent/README.md's "Building" section for the same
// caveat applied to the Rust agent's full binary), but the grepable format
// itself has been stable and documented for well over a decade, so this is
// a reasonable substitute for a live capture.

describe("parseGrepableOutput", () => {
  it("parses open ports with service and version, in the documented field order", () => {
    const raw = [
      "# Nmap 7.94 scan initiated Thu Aug 13 2026 as: nmap -sV -Pn -T4 -p 21,22,25,80,443,3389,8080,8443 -oG out.gnmap example.com",
      "Host: 93.184.216.34 (example.com)\tStatus: Up",
      "Host: 93.184.216.34 (example.com)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu 3ubuntu0.6/, 80/open/tcp//http//nginx 1.18.0/\tIgnored State: closed (6)",
      "# Nmap done at Thu Aug 13 2026 -- 1 IP address (1 host up) scanned in 12.34 seconds",
    ].join("\n");

    const result = parseGrepableOutput(raw);

    expect(result).toEqual([
      { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.6" },
      { port: 80, protocol: "tcp", service: "http", version: "nginx 1.18.0" },
    ]);
  });

  it("excludes closed and filtered ports — only 'open' counts", () => {
    const raw =
      "Host: 10.0.0.1 ()\tPorts: 80/open/tcp//http//nginx/, 8080/closed/tcp//http-proxy///, 8443/filtered/tcp//https-alt///\tIgnored State: closed (5)";

    const result = parseGrepableOutput(raw);

    expect(result).toEqual([{ port: 80, protocol: "tcp", service: "http", version: "nginx" }]);
  });

  it("correctly un-escapes a literal '/' inside a version string instead of treating it as a field separator", () => {
    // Nmap escapes a literal "/" within a field as "\/" for exactly this
    // reason — a version string like "Apache/2.4.41" would otherwise
    // silently shift every field after it.
    const raw = String.raw`Host: 10.0.0.2 ()\tPorts: 80/open/tcp//http//Apache\/2.4.41 (Unix)/`.replace("\\t", "\t");

    const result = parseGrepableOutput(raw);

    expect(result).toEqual([{ port: 80, protocol: "tcp", service: "http", version: "Apache/2.4.41 (Unix)" }]);
  });

  it("handles a host with no open ports at all (empty Ports section)", () => {
    const raw = "Host: 10.0.0.3 ()\tPorts: \tIgnored State: closed (8)";
    expect(parseGrepableOutput(raw)).toEqual([]);
  });

  it("returns [] for empty or comment-only input", () => {
    expect(parseGrepableOutput("")).toEqual([]);
    expect(parseGrepableOutput("# Nmap 7.94 scan initiated ...\n# Nmap done ...")).toEqual([]);
  });

  it("reports service/version as null when Nmap couldn't identify them", () => {
    const raw = "Host: 10.0.0.4 ()\tPorts: 22/open/tcp/////\tIgnored State: closed (7)";
    const result = parseGrepableOutput(raw);
    expect(result).toEqual([{ port: 22, protocol: "tcp", service: null, version: null }]);
  });

  it("ignores non-Host lines and Host lines without a Ports field (e.g. a bare Status: Up line)", () => {
    const raw = ["Host: 10.0.0.5 ()\tStatus: Up", "# a comment line", "not a host line at all"].join("\n");
    expect(parseGrepableOutput(raw)).toEqual([]);
  });
});

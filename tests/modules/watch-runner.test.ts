import { describe, it, expect } from "vitest";
import { diffPorts, portsEqual } from "../../src/modules/discovery/watch-runner";

describe("portsEqual", () => {
  it("treats equal sets as equal regardless of order", () => {
    expect(portsEqual([80, 443], [443, 80])).toBe(true);
  });

  it("treats different-length sets as unequal", () => {
    expect(portsEqual([80], [80, 443])).toBe(false);
  });

  it("treats different port numbers as unequal", () => {
    expect(portsEqual([80, 443], [80, 8080])).toBe(false);
  });

  it("treats two empty sets as equal", () => {
    expect(portsEqual([], [])).toBe(true);
  });
});

describe("diffPorts", () => {
  it("reports every current port as PORT_OPENED when there's no previous state (first-ever scan)", () => {
    const changes = diffPorts(null, [{ port: 443, protocol: "tcp", service: "https", version: null }]);
    expect(changes).toEqual([
      {
        kind: "PORT_OPENED",
        summary: "Port 443/tcp opened (https)",
        details: { before: null, after: { port: 443, protocol: "tcp", service: "https", version: null } },
      },
    ]);
  });

  it("reports no changes when nothing differs", () => {
    const snapshot = [{ port: 443, protocol: "tcp", service: "https", version: "1.1" }];
    expect(diffPorts(snapshot, snapshot)).toEqual([]);
  });

  it("reports PORT_OPENED for a newly-open port alongside an unchanged existing one", () => {
    const previous = [{ port: 443, protocol: "tcp", service: "https", version: null }];
    const current = [
      { port: 443, protocol: "tcp", service: "https", version: null },
      { port: 8080, protocol: "tcp", service: "http-proxy", version: null },
    ];
    const changes = diffPorts(previous, current);
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe("PORT_OPENED");
    expect(changes[0].summary).toContain("8080/tcp");
  });

  it("reports PORT_CLOSED for a port that disappeared", () => {
    const previous = [{ port: 21, protocol: "tcp", service: "ftp", version: null }];
    const changes = diffPorts(previous, []);
    expect(changes).toEqual([
      {
        kind: "PORT_CLOSED",
        summary: "Port 21/tcp closed (was ftp)",
        details: { before: previous[0], after: null },
      },
    ]);
  });

  it("reports SERVICE_CHANGED when the same port's service/version banner differs", () => {
    const previous = [{ port: 80, protocol: "tcp", service: "nginx", version: "1.18" }];
    const current = [{ port: 80, protocol: "tcp", service: "nginx", version: "1.24" }];
    const changes = diffPorts(previous, current);
    expect(changes).toEqual([
      {
        kind: "SERVICE_CHANGED",
        summary: "Port 80/tcp service/version changed",
        details: { before: previous[0], after: current[0] },
      },
    ]);
  });

  it("distinguishes the same port number on different protocols", () => {
    const previous = [{ port: 53, protocol: "udp", service: "dns", version: null }];
    const current = [{ port: 53, protocol: "tcp", service: "dns", version: null }];
    const changes = diffPorts(previous, current);
    // Different protocol = a different key entirely: the udp entry closed, a new tcp entry opened.
    expect(changes).toHaveLength(2);
    expect(changes.map((c) => c.kind).sort()).toEqual(["PORT_CLOSED", "PORT_OPENED"]);
  });

  it("can report multiple simultaneous changes in one diff", () => {
    const previous = [
      { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.2" },
      { port: 8080, protocol: "tcp", service: "http-proxy", version: null },
    ];
    const current = [
      { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 9.6" }, // version bumped
      { port: 443, protocol: "tcp", service: "https", version: null }, // newly opened
      // 8080 is gone — closed
    ];
    const changes = diffPorts(previous, current);
    const kinds = changes.map((c) => c.kind).sort();
    expect(kinds).toEqual(["PORT_CLOSED", "PORT_OPENED", "SERVICE_CHANGED"]);
  });
});

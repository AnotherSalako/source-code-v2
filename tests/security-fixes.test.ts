import { describe, it, expect } from "vitest";
import { escapeHtml } from "../src/notifications/providers/resend";
import { escapeMrkdwn } from "../src/notifications/providers/slack";
import { sanitizeFilenameForHeader } from "../src/modules/evidence/evidence.routes";

// Regression coverage for the three input-handling fixes made this session —
// each closes a real injection path that was found by code review, not a
// hypothetical.

describe("escapeHtml (email notification body)", () => {
  it("neutralizes a script/img-based HTML injection in a finding title", () => {
    const malicious = '<img src=x onerror="alert(document.cookie)">';
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain("<img");
    expect(escaped).toBe("&lt;img src=x onerror=&quot;alert(document.cookie)&quot;&gt;");
  });

  it("escapes a phishing anchor tag in a client name", () => {
    const escaped = escapeHtml('<a href="https://evil.example">Click to verify</a>');
    expect(escaped).not.toContain("<a href");
  });

  it("leaves ordinary text untouched", () => {
    expect(escapeHtml("SQL Injection on /login")).toBe("SQL Injection on /login");
  });
});

describe("escapeMrkdwn (Slack notification body)", () => {
  it("neutralizes Slack link syntax so a title can't become a clickable phishing link", () => {
    const malicious = "<https://evil.example|Click here to verify your account>";
    const escaped = escapeMrkdwn(malicious);
    expect(escaped).not.toMatch(/^<https/);
    expect(escaped).toBe("&lt;https://evil.example|Click here to verify your account&gt;");
  });

  it("leaves ordinary text untouched", () => {
    expect(escapeMrkdwn("Weak HTTP Strict-Transport-Security")).toBe("Weak HTTP Strict-Transport-Security");
  });
});

describe("sanitizeFilenameForHeader (evidence download Content-Disposition)", () => {
  it("strips a double quote that would break out of the quoted filename value", () => {
    const malicious = 'evidence.png"; filename="smuggled.exe';
    expect(sanitizeFilenameForHeader(malicious)).toBe("evidence.png; filename=smuggled.exe");
  });

  it("strips CRLF that would attempt HTTP header injection", () => {
    const malicious = "evidence.png\r\nX-Injected-Header: evil";
    const sanitized = sanitizeFilenameForHeader(malicious);
    expect(sanitized).not.toContain("\r");
    expect(sanitized).not.toContain("\n");
  });

  it("leaves an ordinary filename untouched", () => {
    expect(sanitizeFilenameForHeader("screenshot-2026-08-10.png")).toBe("screenshot-2026-08-10.png");
  });
});

import { ComplianceFramework } from "@prisma/client";

// Deterministic, keyword-based mapping from a finding's title to the
// controls it's plausible evidence against — not authoritative, not a
// replacement for a consultant's own judgment, and deliberately willing to
// return nothing rather than force every finding into a bucket it doesn't
// really belong in. Same "surfaces a structural signal, human decides
// what it means" precedent as clustering, WatchAlert, CspmIssue, and the
// false-positive score: this never writes to a ComplianceCheck's status
// itself, only suggests which controls a finding is worth checking against.
//
// A finding can plausibly map to more than one control (a hardcoded
// credential finding is both an authentication problem and a secure-coding
// problem) — every keyword match is returned, not just the first.

export interface MappedControl {
  framework: ComplianceFramework;
  controlId: string;
  controlName: string;
}

interface ControlMappingRule extends MappedControl {
  keywords: string[]; // case-insensitive substring match against the finding title; any one match is enough
}

const RULES: ControlMappingRule[] = [
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.28",
    controlName: "Secure coding",
    keywords: ["sql injection", "xss", "cross-site scripting", "code execution", "deserialization", "command injection", "path traversal", "ssrf", "buffer overflow"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.5.15",
    controlName: "Access control",
    keywords: ["access control", "authorization", "privilege escalation", "idor", "insecure direct object"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.5",
    controlName: "Secure authentication",
    keywords: ["authentication", "password", "credential", "mfa", "multi-factor", "session fixation", "session hijack", "weak login"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.24",
    controlName: "Use of cryptography",
    keywords: ["tls", "ssl", "encrypt", "cleartext", "plaintext", "weak cipher", "certificate", "hardcoded key"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.8",
    controlName: "Management of technical vulnerabilities",
    keywords: ["outdated", "vulnerable version", "unpatched", "end of life", "eol", "known vulnerability"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.15",
    controlName: "Logging",
    keywords: ["logging", "audit log", "log injection", "insufficient logging"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.7",
    controlName: "Protection against malware",
    keywords: ["malware", "virus", "trojan", "ransomware"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.20",
    controlName: "Networks security",
    keywords: ["open port", "firewall", "network segmentation", "exposed service", "unnecessary port"],
  },
  {
    framework: ComplianceFramework.ISO27001,
    controlId: "A.8.9",
    controlName: "Configuration management",
    keywords: ["misconfigur", "default credential", "default password", "insecure default", "security header"],
  },
  {
    framework: ComplianceFramework.NDPR,
    controlId: "NDPR.18",
    controlName: "Technical safeguards implemented (encryption, access control)",
    keywords: ["personal data", "pii", "data exposure", "data leak"],
  },
];

export function mapFindingToControls(title: string): MappedControl[] {
  const lower = title.toLowerCase();
  return RULES.filter((rule) => rule.keywords.some((kw) => lower.includes(kw))).map(({ framework, controlId, controlName }) => ({
    framework,
    controlId,
    controlName,
  }));
}

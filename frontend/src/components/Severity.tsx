import type { Severity, FindingStatus, EngagementStatus, TestStatus, ComplianceStatus } from "../lib/types";

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--color-risk-critical)",
  HIGH: "var(--color-risk-high)",
  MEDIUM: "var(--color-risk-medium)",
  LOW: "var(--color-risk-low)",
  INFO: "var(--color-ink-faint)",
};

export function SeverityDot({ severity }: { severity: Severity }) {
  return <span className="inline-block h-2 w-2 rounded-full" style={{ background: SEVERITY_COLOR[severity] }} />;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-line-soft bg-surface px-2.5 py-1 text-xs font-semibold"
      style={{ color: SEVERITY_COLOR[severity] }}
    >
      <SeverityDot severity={severity} />
      {severity}
    </span>
  );
}

const STATUS_LABEL: Record<string, string> = {
  OPEN: "Open",
  REMEDIATING: "Remediating",
  RETESTED_PASS: "Fixed — verified",
  RETESTED_FAIL: "Not fixed",
  ACCEPTED_RISK: "Accepted risk",
  SCOPING: "Scoping",
  ACTIVE: "Active",
  REPORTING: "Reporting",
  RETEST: "Retest",
  CLOSED: "Closed",
  PLANNED: "Planned",
  IN_PROGRESS: "In progress",
  COMPLETE: "Complete",
  PASS: "Pass",
  FAIL: "Fail",
  PARTIAL: "Partial",
  NOT_APPLICABLE: "N/A",
  PENDING: "Not yet assessed",
  SCHEDULED: "Scheduled",
  CANCELLED: "Cancelled",
};

export function StatusPill({ status }: { status: FindingStatus | EngagementStatus | TestStatus | ComplianceStatus | string }) {
  const isGood = status === "RETESTED_PASS" || status === "COMPLETE" || status === "CLOSED" || status === "PASS";
  const isBad = status === "RETESTED_FAIL" || status === "FAIL" || status === "OPEN";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${
        isGood ? "bg-secure/10 text-secure" : isBad ? "bg-risk-critical/10 text-[color:var(--color-risk-critical)]" : "bg-line-soft text-ink-soft"
      }`}
    >
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

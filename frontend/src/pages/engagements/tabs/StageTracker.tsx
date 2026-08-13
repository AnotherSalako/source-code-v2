import { useEffect, useState } from "react";
import { api } from "../../../lib/api";
import type { Engagement, Finding, Report, Test } from "../../../lib/types";
import { Card, SectionLabel } from "../../../components/ui";

interface Stage {
  key: string;
  label: string;
  done: boolean;
}

const STAGE_DEFS: { key: string; label: string }[] = [
  { key: "scoping", label: "Scoping" },
  { key: "authorized", label: "Authorized" },
  { key: "testing", label: "Testing" },
  { key: "findings", label: "Findings identified" },
  { key: "remediation", label: "Remediation" },
  { key: "retested", label: "Retested" },
  { key: "delivered", label: "Report delivered" },
];

const RETESTED_STATUSES = new Set(["RETESTED_PASS", "RETESTED_FAIL"]);

/**
 * Derived entirely from data that already exists (tests/findings/reports) —
 * deliberately not a manually-set "current stage" field, so it can never
 * drift out of sync with reality the way a hand-maintained status would.
 * Visible to every role, but this is specifically what turns "a tool you
 * use on the client's behalf" into "a platform they can check themselves":
 * exec_client already has read access to every endpoint this calls.
 */
export function StageTracker({ engagement }: { engagement: Engagement }) {
  const [tests, setTests] = useState<Test[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.get<Test[]>(`/engagements/${engagement.id}/tests`),
      api.get<Finding[]>(`/engagements/${engagement.id}/findings`),
      api.get<Report[]>(`/engagements/${engagement.id}/reports`),
    ])
      .then(([t, f, r]) => {
        setTests(t);
        setFindings(f);
        setReports(r);
      })
      .finally(() => setLoading(false));
  }, [engagement.id]);

  if (loading) return <div className="h-20 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />;

  const done: Record<string, boolean> = {
    scoping: true,
    authorized: Boolean(engagement.authorizationSignedAt),
    testing: tests.length > 0,
    findings: findings.length > 0,
    remediation: findings.some((f) => f.status !== "OPEN"),
    retested: findings.some((f) => RETESTED_STATUSES.has(f.status)),
    delivered: reports.length > 0,
  };

  const stages: Stage[] = STAGE_DEFS.map((s) => ({ ...s, done: done[s.key] }));
  const currentIndex = stages.reduce((lastDone, s, i) => (s.done ? i : lastDone), 0);

  return (
    <Card className="flex flex-col gap-4">
      <SectionLabel>Engagement status</SectionLabel>
      <div className="flex flex-wrap items-center gap-x-1 gap-y-3">
        {stages.map((stage, i) => (
          <div key={stage.key} className="flex items-center gap-1">
            <div
              className={`flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-semibold transition-colors ${
                stage.done
                  ? i === currentIndex
                    ? "bg-ink text-paper"
                    : "bg-secure/10 text-secure"
                  : "bg-line-soft text-ink-faint"
              }`}
            >
              <span
                className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] ${
                  stage.done ? "bg-paper/20" : "border border-ink-faint/40"
                }`}
              >
                {stage.done ? "✓" : ""}
              </span>
              {stage.label}
            </div>
            {i < stages.length - 1 && <span className="h-px w-4 bg-line-soft" />}
          </div>
        ))}
      </div>
      <p className="text-xs text-ink-faint">
        {stages[currentIndex]?.done
          ? `Current stage: ${stages[currentIndex].label}.`
          : "This engagement hasn't been authorized yet — testing can't start until it is."}
      </p>
    </Card>
  );
}

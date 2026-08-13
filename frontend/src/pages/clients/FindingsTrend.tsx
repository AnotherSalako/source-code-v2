import { useEffect, useState } from "react";
import { api } from "../../lib/api";
import type { FindingsHistory, Severity } from "../../lib/types";
import { Card, EmptyState, SectionLabel } from "../../components/ui";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_VAR: Record<Severity, string> = {
  CRITICAL: "var(--color-risk-critical)",
  HIGH: "var(--color-risk-high)",
  MEDIUM: "var(--color-risk-medium)",
  LOW: "var(--color-risk-low)",
  INFO: "var(--color-ink-faint)",
};

const STATUS_LABEL: Record<string, string> = {
  OPEN: "Open",
  REMEDIATING: "Remediating",
  RETESTED_PASS: "Fixed — verified",
  RETESTED_FAIL: "Not fixed",
  ACCEPTED_RISK: "Accepted risk",
};

/**
 * What makes a retainer worth more than a series of one-off assessments:
 * whether risk is trending up or down across engagements, and whether the
 * same issue keeps coming back unfixed. Pulled from GET
 * /clients/:id/findings-history, which is metadata-only (title/severity/
 * status/assetId, no *Enc field) — safe for every role including
 * exec_client, same as the per-engagement findings list.
 */
export function FindingsTrend({ clientId }: { clientId: string }) {
  const [data, setData] = useState<FindingsHistory | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .get<FindingsHistory>(`/clients/${clientId}/findings-history`)
      .then(setData)
      .finally(() => setLoading(false));
  }, [clientId]);

  if (loading) return <div className="h-40 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />;
  if (!data || data.totalFindings === 0) {
    return (
      <Card>
        <SectionLabel>Findings trend</SectionLabel>
        <EmptyState title="No findings yet" hint="Trends across engagements will appear here once testing starts." />
      </Card>
    );
  }

  const maxPerEngagement = Math.max(1, ...data.byEngagement.map((e) => e.total));

  return (
    <Card className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <SectionLabel>Findings trend across engagements</SectionLabel>
        <span className="text-xs text-ink-faint">{data.totalFindings} total findings</span>
      </div>

      {data.byEngagement.length > 1 && (
        <div>
          <p className="mb-2 text-xs font-medium text-ink-soft">Risk over time</p>
          <div className="flex items-end gap-2" style={{ height: "88px" }}>
            {data.byEngagement.map((e) => (
              <div key={e.engagementId} className="flex flex-1 flex-col items-center gap-1.5" title={`${e.total} findings`}>
                <div className="flex w-full flex-1 flex-col-reverse overflow-hidden rounded-md" style={{ height: `${(e.total / maxPerEngagement) * 72 + 4}px` }}>
                  {SEVERITY_ORDER.filter((s) => e.counts[s]).map((s) => (
                    <div
                      key={s}
                      style={{
                        background: SEVERITY_VAR[s],
                        height: `${((e.counts[s] ?? 0) / e.total) * 100}%`,
                      }}
                    />
                  ))}
                </div>
                <span className="text-[10px] text-ink-faint">
                  {new Date(e.engagementCreatedAt).toLocaleDateString(undefined, { month: "short", year: "2-digit" })}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        <div>
          <p className="mb-2 text-xs font-medium text-ink-soft">By severity</p>
          <div className="flex flex-col gap-1.5">
            {SEVERITY_ORDER.filter((s) => data.bySeverity[s]).map((s) => (
              <div key={s} className="flex items-center gap-2 text-sm">
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_VAR[s] }} />
                <span className="text-ink-soft">{s}</span>
                <span className="ml-auto font-medium text-ink">{data.bySeverity[s]}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <p className="mb-2 text-xs font-medium text-ink-soft">By status</p>
          <div className="flex flex-col gap-1.5">
            {Object.entries(data.byStatus).map(([status, count]) => (
              <div key={status} className="flex items-center gap-2 text-sm">
                <span className="text-ink-soft">{STATUS_LABEL[status] ?? status}</span>
                <span className="ml-auto font-medium text-ink">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {data.recurring.length > 0 && (
        <div>
          <p className="mb-2 text-xs font-medium text-ink-soft">
            Recurring — same issue found in more than one engagement, not fixed between assessments
          </p>
          <ul className="flex flex-col gap-1.5">
            {data.recurring.map((r) => (
              <li key={`${r.assetId}::${r.title}`} className="flex items-center justify-between rounded-xl bg-[color:var(--color-risk-critical)]/5 px-3 py-2 text-sm">
                <span className="truncate text-ink">{r.title}</span>
                <span className="shrink-0 text-xs font-semibold text-[color:var(--color-risk-critical)]">
                  {r.occurrences}× engagements
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

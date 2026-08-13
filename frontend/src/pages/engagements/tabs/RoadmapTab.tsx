import { useEffect, useState } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { RemediationEffort, RoadmapItem } from "../../../lib/types";
import { Card, EmptyState, inputClass } from "../../../components/ui";
import { SeverityBadge } from "../../../components/Severity";

const EFFORT_OPTIONS: RemediationEffort[] = ["QUICK_WIN", "SMALL", "MEDIUM", "LARGE"];

const BUCKETS: { key: RoadmapItem["bucket"]; title: string; hint?: string }[] = [
  { key: "quick_win", title: "Quick wins", hint: "High value, low effort — do these first" },
  { key: "plan", title: "Plan in" },
  { key: "long_term", title: "Long-term projects", hint: "Larger effort, schedule accordingly" },
  { key: "uncategorized", title: "Not yet estimated", hint: "Set an effort level to place these on the roadmap" },
];

export function RoadmapTab({ engagementId }: { engagementId: string }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [items, setItems] = useState<RoadmapItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function reload() {
    setLoading(true);
    api
      .get<RoadmapItem[]>(`/engagements/${engagementId}/roadmap`)
      .then(setItems)
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  async function setEffort(findingId: string, effort: RemediationEffort) {
    setError(null);
    try {
      await api.patch(`/findings/${findingId}`, { remediationEffort: effort });
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't update effort.");
    }
  }

  if (loading) return <div className="h-48 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />;
  if (items.length === 0) {
    return <EmptyState title="Nothing on the roadmap" hint="Open findings will show up here once logged." />;
  }

  return (
    <div className="flex flex-col gap-5">
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      {BUCKETS.map(({ key, title, hint }) => {
        const bucketItems = items.filter((i) => i.bucket === key);
        if (bucketItems.length === 0) return null;
        return (
          <Card key={key}>
            <div className="mb-4 flex items-baseline justify-between">
              <p className="text-sm font-semibold text-ink">{title}</p>
              {hint && <p className="text-xs text-ink-faint">{hint}</p>}
            </div>
            <ul className="flex flex-col gap-1">
              {bucketItems.map((item) => (
                <li key={item.id} className="flex items-center justify-between gap-3 rounded-xl px-2 py-2 hover:bg-line-soft">
                  <span className="flex min-w-0 items-center gap-2.5">
                    <SeverityBadge severity={item.severity} />
                    <span className="truncate text-sm text-ink">{item.title}</span>
                  </span>
                  {isAdmin && (
                    <select
                      value={item.remediationEffort ?? ""}
                      onChange={(e) => setEffort(item.id, e.target.value as RemediationEffort)}
                      className={`${inputClass} w-36 shrink-0 !py-1.5 text-xs`}
                    >
                      <option value="" disabled>
                        Set effort
                      </option>
                      {EFFORT_OPTIONS.map((e) => (
                        <option key={e} value={e}>
                          {e.replace("_", " ")}
                        </option>
                      ))}
                    </select>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        );
      })}
    </div>
  );
}

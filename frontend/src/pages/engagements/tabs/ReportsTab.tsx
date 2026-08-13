import { useEffect, useState } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { Report, ReportType } from "../../../lib/types";
import { Button, Card, EmptyState } from "../../../components/ui";

const REPORT_TYPES: { value: ReportType; label: string; hint: string }[] = [
  { value: "EXECUTIVE", label: "Executive summary", hint: "Board-level business risk view" },
  { value: "TECHNICAL", label: "Technical report", hint: "Full findings, evidence pointers, remediation" },
  { value: "RETEST_ADDENDUM", label: "Retest addendum", hint: "Verification results after fixes" },
];

export function ReportsTab({ engagementId }: { engagementId: string }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<ReportType | null>(null);
  const [error, setError] = useState<string | null>(null);

  function reload() {
    setLoading(true);
    api
      .get<Report[]>(`/engagements/${engagementId}/reports`)
      .then(setReports)
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  async function handleGenerate(type: ReportType) {
    setError(null);
    setGenerating(type);
    try {
      await api.post(`/engagements/${engagementId}/reports/generate`, { type });
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't generate the report.");
    } finally {
      setGenerating(null);
    }
  }

  async function handleDownload(report: Report) {
    const blob = await api.downloadBlob(`/reports/${report.id}/download`);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.type.toLowerCase()}-v${report.version}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-5">
      {isAdmin && (
        <Card>
          <p className="mb-4 text-sm font-medium text-ink-soft">Generate a report</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {REPORT_TYPES.map((rt) => (
              <button
                key={rt.value}
                onClick={() => handleGenerate(rt.value)}
                disabled={generating !== null}
                className="rounded-2xl border border-line-soft bg-paper p-4 text-left transition-colors hover:border-ink/20 disabled:opacity-50"
              >
                <p className="text-sm font-semibold text-ink">{rt.label}</p>
                <p className="mt-1 text-xs text-ink-faint">{rt.hint}</p>
                <p className="mt-3 text-xs font-semibold text-ink-soft">
                  {generating === rt.value ? "Generating…" : "Generate →"}
                </p>
              </button>
            ))}
          </div>
          {error && <p className="mt-3 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
        </Card>
      )}

      {loading ? (
        <div className="h-24 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
      ) : reports.length === 0 ? (
        <EmptyState title="No reports generated yet" hint="Generated PDFs are encrypted at rest and decrypted only at download." />
      ) : (
        <Card className="overflow-hidden !p-0">
          <ul>
            {reports.map((report) => (
              <li key={report.id} className="border-b border-line-soft last:border-0">
                <button
                  onClick={() => handleDownload(report)}
                  className="flex w-full items-center justify-between gap-4 px-5 py-3.5 text-left transition-colors hover:bg-line-soft"
                >
                  <span>
                    <span className="text-sm font-medium text-ink">
                      {REPORT_TYPES.find((rt) => rt.value === report.type)?.label ?? report.type} · v{report.version}
                    </span>
                    <span className="ml-2 text-xs text-ink-faint">
                      {new Date(report.generatedAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
                    </span>
                  </span>
                  <Button variant="outline">Download ↓</Button>
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

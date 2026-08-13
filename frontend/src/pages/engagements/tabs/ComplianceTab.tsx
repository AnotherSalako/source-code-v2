import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { ComplianceCheck, ComplianceFramework, ComplianceStatus, ComplianceSummary } from "../../../lib/types";
import { Button, Card, EmptyState, Field, inputClass } from "../../../components/ui";
import { StatusPill } from "../../../components/Severity";

const FRAMEWORKS: ComplianceFramework[] = ["NDPR", "ISO27001", "PCI_DSS", "OTHER"];
const STATUSES: ComplianceStatus[] = ["PENDING", "PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE"];
const LIBRARY_FRAMEWORKS: ComplianceFramework[] = ["NDPR", "ISO27001"]; // frameworks with a standard control list to seed from

export function ComplianceTab({ engagementId }: { engagementId: string }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [checks, setChecks] = useState<ComplianceCheck[]>([]);
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [gapsOnly, setGapsOnly] = useState(false);
  const [seeding, setSeeding] = useState<ComplianceFramework | null>(null);
  const [error, setError] = useState<string | null>(null);

  function reload() {
    setLoading(true);
    Promise.all([
      api.get<ComplianceCheck[]>(`/engagements/${engagementId}/compliance-checks`),
      api.get<ComplianceSummary>(`/engagements/${engagementId}/compliance-summary`),
    ])
      .then(([c, s]) => {
        setChecks(c);
        setSummary(s);
      })
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  async function seedLibrary(framework: ComplianceFramework) {
    setError(null);
    setSeeding(framework);
    try {
      await api.post(`/engagements/${engagementId}/compliance-checks/seed`, { framework });
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't load the standard checklist.");
    } finally {
      setSeeding(null);
    }
  }

  async function updateStatus(id: string, status: ComplianceStatus) {
    await api.patch(`/compliance-checks/${id}`, { status });
    reload();
  }

  const visibleChecks = gapsOnly ? checks.filter((c) => c.status === "FAIL" || c.status === "PARTIAL") : checks;

  return (
    <div className="flex flex-col gap-5">
      {summary && summary.totalControls > 0 && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Object.entries(summary.byFramework).map(([framework, counts]) => (
            <Card key={framework} className="text-center">
              <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">{framework}</p>
              <p className="mt-2 text-2xl font-extrabold text-ink">{counts.PASS ?? 0}</p>
              <p className="text-xs text-ink-faint">passed of {Object.values(counts).reduce((a, b) => a + b, 0)}</p>
            </Card>
          ))}
        </div>
      )}

      {isAdmin && (
        <Card>
          <p className="mb-3 text-sm font-medium text-ink-soft">Load a standard checklist</p>
          <div className="flex flex-wrap gap-2">
            {LIBRARY_FRAMEWORKS.map((f) => (
              <Button key={f} variant="outline" onClick={() => seedLibrary(f)} disabled={seeding !== null}>
                {seeding === f ? "Loading…" : `Load ${f} controls`}
              </Button>
            ))}
          </div>
          {error && <p className="mt-3 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
        </Card>
      )}

      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2 text-sm text-ink-soft">
          <input type="checkbox" checked={gapsOnly} onChange={(e) => setGapsOnly(e.target.checked)} className="h-4 w-4 rounded" />
          Show gaps only (fail / partial)
        </label>
        {isAdmin && (
          <Button variant="outline" onClick={() => setShowForm((s) => !s)}>
            {showForm ? "Cancel" : "+ Log control"}
          </Button>
        )}
      </div>

      {showForm && (
        <Card>
          <NewCheckForm
            engagementId={engagementId}
            onCreated={() => {
              setShowForm(false);
              reload();
            }}
          />
        </Card>
      )}

      {loading ? (
        <div className="h-32 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
      ) : visibleChecks.length === 0 ? (
        <EmptyState
          title={gapsOnly ? "No gaps — everything passing or n/a" : "No compliance controls logged yet"}
          hint={gapsOnly ? undefined : "Load a standard checklist above, or log gaps against NDPR, ISO 27001, or another framework by hand."}
        />
      ) : (
        <Card className="overflow-hidden !p-0">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-line-soft text-xs uppercase tracking-wide text-ink-faint">
                <th className="px-5 py-3 font-medium">Control</th>
                <th className="px-5 py-3 font-medium">Framework</th>
                <th className="px-5 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {visibleChecks.map((c) => (
                <tr key={c.id} className="border-b border-line-soft last:border-0">
                  <td className="px-5 py-3">
                    <p className="font-medium text-ink">{c.controlName}</p>
                    <p className="font-mono text-xs text-ink-faint">{c.controlId}</p>
                  </td>
                  <td className="px-5 py-3 text-ink-soft">{c.framework}</td>
                  <td className="px-5 py-3">
                    {isAdmin ? (
                      <select
                        value={c.status}
                        onChange={(e) => updateStatus(c.id, e.target.value as ComplianceStatus)}
                        className={`${inputClass} !py-1.5 text-xs`}
                      >
                        {STATUSES.map((s) => (
                          <option key={s} value={s}>
                            {s.replace(/_/g, " ")}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <StatusPill status={c.status} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function NewCheckForm({ engagementId, onCreated }: { engagementId: string; onCreated: () => void }) {
  const [framework, setFramework] = useState<ComplianceFramework>("NDPR");
  const [controlId, setControlId] = useState("");
  const [controlName, setControlName] = useState("");
  const [status, setStatus] = useState<ComplianceStatus>("FAIL");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/engagements/${engagementId}/compliance-checks`, {
        framework,
        controlId,
        controlName,
        status,
        notes: notes || undefined,
      });
      setControlId("");
      setControlName("");
      setNotes("");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't log the control.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <Field label="Framework">
        <select value={framework} onChange={(e) => setFramework(e.target.value as ComplianceFramework)} className={inputClass}>
          {FRAMEWORKS.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Status">
        <select value={status} onChange={(e) => setStatus(e.target.value as ComplianceStatus)} className={inputClass}>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Control ID">
        <input required value={controlId} onChange={(e) => setControlId(e.target.value)} className={inputClass} placeholder="A.8.15" />
      </Field>
      <Field label="Control name">
        <input
          required
          value={controlName}
          onChange={(e) => setControlName(e.target.value)}
          className={inputClass}
          placeholder="Logging"
        />
      </Field>
      <div className="sm:col-span-2">
        <Field label="Notes (encrypted at rest)">
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} className={`${inputClass} min-h-16`} />
        </Field>
      </div>
      {error && <p className="sm:col-span-2 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div className="sm:col-span-2">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Logging…" : "Log control"}
        </Button>
      </div>
    </form>
  );
}

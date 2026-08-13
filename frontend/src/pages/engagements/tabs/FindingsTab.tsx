import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { Asset, Finding, Severity, Test } from "../../../lib/types";
import { Button, Card, EmptyState, Field, inputClass } from "../../../components/ui";
import { SeverityBadge, StatusPill } from "../../../components/Severity";
import { FindingDetail } from "./FindingDetail";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function FindingsTab({ engagementId, authorized }: { engagementId: string; authorized: boolean }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tests, setTests] = useState<Test[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  function reload() {
    setLoading(true);
    Promise.all([
      api.get<Finding[]>(`/engagements/${engagementId}/findings`),
      api.get<Test[]>(`/engagements/${engagementId}/tests`),
      api.get<Asset[]>(`/engagements/${engagementId}/assets`),
    ])
      .then(([f, t, a]) => {
        setFindings(f);
        setTests(t);
        setAssets(a);
      })
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  return (
    <div className="flex flex-col gap-5">
      {isAdmin && authorized && (
        <div className="flex justify-end">
          <Button variant="outline" onClick={() => setShowForm((s) => !s)} disabled={tests.length === 0}>
            {showForm ? "Cancel" : "+ Log finding"}
          </Button>
        </div>
      )}

      {tests.length === 0 && isAdmin && (
        <p className="text-sm text-ink-faint">Log a test first (Tests tab) before recording findings against it.</p>
      )}

      {showForm && (
        <Card>
          <NewFindingForm
            tests={tests}
            assets={assets}
            onCreated={() => {
              setShowForm(false);
              reload();
            }}
          />
        </Card>
      )}

      {loading ? (
        <div className="h-32 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
      ) : findings.length === 0 ? (
        <EmptyState title="No findings logged yet" hint="Findings you log will show up here, grouped by severity." />
      ) : (
        <Card className="overflow-hidden !p-0">
          <ul>
            {findings.map((f) => (
              <li key={f.id} className="border-b border-line-soft last:border-0">
                <button
                  onClick={() => setSelectedId(f.id)}
                  className="flex w-full items-center justify-between gap-4 px-5 py-3.5 text-left transition-colors hover:bg-line-soft"
                >
                  <span className="flex min-w-0 items-center gap-3">
                    <SeverityBadge severity={f.severity} />
                    <span className="truncate text-sm font-medium text-ink">{f.title}</span>
                  </span>
                  <StatusPill status={f.status} />
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {selectedId && <FindingDetail findingId={selectedId} onClose={() => { setSelectedId(null); reload(); }} />}
    </div>
  );
}

function NewFindingForm({
  tests,
  assets,
  onCreated,
}: {
  tests: Test[];
  assets: Asset[];
  onCreated: () => void;
}) {
  const [testId, setTestId] = useState(tests[0]?.id ?? "");
  const [assetId, setAssetId] = useState(assets[0]?.id ?? "");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("MEDIUM");
  const [reproductionSteps, setReproductionSteps] = useState("");
  const [remediationGuidance, setRemediationGuidance] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const test = tests.find((t) => t.id === testId);
      await api.post(`/engagements/${test?.engagementId}/tests/${testId}/findings`, {
        assetId,
        title,
        description,
        severity,
        reproductionSteps: reproductionSteps || undefined,
        remediationGuidance: remediationGuidance || undefined,
      });
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't log the finding.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <Field label="Test">
        <select value={testId} onChange={(e) => setTestId(e.target.value)} className={inputClass}>
          {tests.map((t) => (
            <option key={t.id} value={t.id}>
              {t.type.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Asset">
        <select value={assetId} onChange={(e) => setAssetId(e.target.value)} className={inputClass}>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Title">
        <input required value={title} onChange={(e) => setTitle(e.target.value)} className={inputClass} placeholder="Reflected XSS on search" />
      </Field>
      <Field label="Severity">
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={inputClass}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Field>
      <div className="sm:col-span-2">
        <Field label="Description (encrypted at rest)">
          <textarea
            required
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className={`${inputClass} min-h-20`}
          />
        </Field>
      </div>
      <Field label="Reproduction steps (encrypted at rest)">
        <textarea
          value={reproductionSteps}
          onChange={(e) => setReproductionSteps(e.target.value)}
          className={`${inputClass} min-h-16`}
        />
      </Field>
      <Field label="Remediation guidance (encrypted at rest)">
        <textarea
          value={remediationGuidance}
          onChange={(e) => setRemediationGuidance(e.target.value)}
          className={`${inputClass} min-h-16`}
        />
      </Field>
      {error && <p className="sm:col-span-2 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div className="sm:col-span-2">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Logging…" : "Log finding"}
        </Button>
      </div>
    </form>
  );
}

import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { Asset, Test, TestType } from "../../../lib/types";
import { Button, Card, EmptyState, Field, inputClass } from "../../../components/ui";
import { StatusPill } from "../../../components/Severity";

const TEST_TYPES: TestType[] = ["VULN_SCAN", "PENTEST", "COMPLIANCE_REVIEW"];

export function TestsTab({ engagementId, authorized }: { engagementId: string; authorized: boolean }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [tests, setTests] = useState<Test[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  function reload() {
    setLoading(true);
    Promise.all([
      api.get<Test[]>(`/engagements/${engagementId}/tests`),
      api.get<Asset[]>(`/engagements/${engagementId}/assets`),
    ])
      .then(([t, a]) => {
        setTests(t);
        setAssets(a);
      })
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  return (
    <div className="flex flex-col gap-5">
      {!authorized && (
        <p className="rounded-2xl bg-[color:var(--color-risk-critical)]/10 px-4 py-3 text-sm text-[color:var(--color-risk-critical)]">
          This engagement isn't authorized yet — new tests can't be created until it is (see Overview).
        </p>
      )}

      {isAdmin && authorized && (
        <div className="flex justify-end">
          <Button variant="outline" onClick={() => setShowForm((s) => !s)} disabled={assets.length === 0}>
            {showForm ? "Cancel" : "+ Log test"}
          </Button>
        </div>
      )}

      {showForm && (
        <Card>
          <NewTestForm
            engagementId={engagementId}
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
      ) : tests.length === 0 ? (
        <EmptyState title="No tests logged yet" hint="Once authorized, log each scan or pentest activity here." />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {tests.map((test) => {
            const asset = assets.find((a) => a.id === test.assetId);
            return (
              <Card key={test.id} className="flex flex-col gap-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">{test.type.replace(/_/g, " ")}</p>
                <p className="truncate text-sm font-medium text-ink">{asset?.name ?? "Unknown asset"}</p>
                {test.toolUsed && <p className="text-xs text-ink-faint">{test.toolUsed}</p>}
                <div className="mt-1">
                  <StatusPill status={test.status} />
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function NewTestForm({
  engagementId,
  assets,
  onCreated,
}: {
  engagementId: string;
  assets: Asset[];
  onCreated: () => void;
}) {
  const [assetId, setAssetId] = useState(assets[0]?.id ?? "");
  const [type, setType] = useState<TestType>("VULN_SCAN");
  const [toolUsed, setToolUsed] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/engagements/${engagementId}/tests`, { assetId, type, toolUsed: toolUsed || undefined });
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't log the test.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-4">
      <Field label="Asset">
        <select value={assetId} onChange={(e) => setAssetId(e.target.value)} className={inputClass}>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Type">
        <select value={type} onChange={(e) => setType(e.target.value as TestType)} className={inputClass}>
          {TEST_TYPES.map((t) => (
            <option key={t} value={t}>
              {t.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Tool used">
        <input value={toolUsed} onChange={(e) => setToolUsed(e.target.value)} className={inputClass} placeholder="Burp Suite, Nessus…" />
      </Field>
      {error && <p className="sm:col-span-4 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div className="sm:col-span-4">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Logging…" : "Log test"}
        </Button>
      </div>
    </form>
  );
}

import { Fragment, useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { Asset, AssetType, Criticality, Finding, ScanJob, Severity, Test, TestType, VerificationMethod } from "../../../lib/types";
import { Button, Card, EmptyState, Field, inputClass, Pill } from "../../../components/ui";
import { SeverityBadge } from "../../../components/Severity";

const ASSET_TYPES: AssetType[] = ["WEB", "MOBILE", "SERVER", "CLOUD", "NETWORK", "API"];
const CRITICALITIES: Criticality[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SCANNABLE_TYPES: AssetType[] = ["WEB", "API"];
const MANUAL_TEST_TYPES: TestType[] = ["PENTEST", "VULN_SCAN", "COMPLIANCE_REVIEW"];
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function AssetsTab({ engagementId, authorized }: { engagementId: string; authorized: boolean }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [assets, setAssets] = useState<Asset[]>([]);
  const [tests, setTests] = useState<Test[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [verifyingAssetId, setVerifyingAssetId] = useState<string | null>(null);
  const [manualTestAssetId, setManualTestAssetId] = useState<string | null>(null);
  const [scanJobs, setScanJobs] = useState<Record<string, ScanJob>>({}); // latest job per assetId
  const pollTimers = useRef<Record<string, number>>({});

  function reloadTests() {
    api.get<Test[]>(`/engagements/${engagementId}/tests`).then(setTests).catch(() => {});
  }

  function reload() {
    setLoading(true);
    api
      .get<Asset[]>(`/engagements/${engagementId}/assets`)
      .then(setAssets)
      .finally(() => setLoading(false));
  }

  function reloadScanJobs() {
    api
      .get<ScanJob[]>(`/engagements/${engagementId}/scan-jobs`)
      .then((jobs) => {
        const latest: Record<string, ScanJob> = {};
        for (const job of jobs) {
          if (!latest[job.assetId] || job.createdAt > latest[job.assetId].createdAt) latest[job.assetId] = job;
        }
        setScanJobs(latest);
        for (const job of Object.values(latest)) {
          if (job.status === "QUEUED" || job.status === "RUNNING") pollJob(job.id, job.assetId);
        }
      })
      .catch(() => {});
  }

  useEffect(reload, [engagementId]);
  useEffect(reloadScanJobs, [engagementId]);
  useEffect(reloadTests, [engagementId]);
  useEffect(() => {
    const timers = pollTimers.current;
    return () => {
      Object.values(timers).forEach((id) => window.clearTimeout(id));
    };
  }, []);

  function pollJob(scanJobId: string, assetId: string) {
    if (pollTimers.current[assetId]) window.clearTimeout(pollTimers.current[assetId]);
    const tick = async () => {
      try {
        const job = await api.get<ScanJob>(`/scan-jobs/${scanJobId}`);
        setScanJobs((prev) => ({ ...prev, [assetId]: job }));
        if (job.status === "QUEUED" || job.status === "RUNNING") {
          pollTimers.current[assetId] = window.setTimeout(tick, 3000);
        } else if (job.status === "COMPLETE") {
          reload(); // new findings landed — refresh so other tabs/badges pick them up too
        }
      } catch {
        // transient — try again on the next tick rather than giving up
        pollTimers.current[assetId] = window.setTimeout(tick, 5000);
      }
    };
    tick();
  }

  async function startScan(assetId: string) {
    try {
      const { scanJobId } = await api.post<{ scanJobId: string }>(`/engagements/${engagementId}/assets/${assetId}/scan`);
      setScanJobs((prev) => ({
        ...prev,
        [assetId]: { id: scanJobId, assetId, testId: null, tool: "nuclei", status: "QUEUED", startedAt: null, completedAt: null, errorMessage: null, findingsCreated: null, findingsSkipped: null, createdAt: new Date().toISOString() },
      }));
      pollJob(scanJobId, assetId);
    } catch (err) {
      alert(err instanceof ApiError ? err.message : "Couldn't start the scan.");
    }
  }

  return (
    <div className="flex flex-col gap-5">
      {isAdmin && (
        <div className="flex justify-end">
          <Button variant="outline" onClick={() => setShowForm((s) => !s)}>
            {showForm ? "Cancel" : "+ Add asset"}
          </Button>
        </div>
      )}

      {showForm && (
        <Card>
          <NewAssetForm
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
      ) : assets.length === 0 ? (
        <EmptyState title="No assets in scope yet" hint="Add the systems, apps, and networks covered by this engagement." />
      ) : (
        <Card className="overflow-hidden !p-0">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-line-soft text-xs uppercase tracking-wide text-ink-faint">
                <th className="px-5 py-3 font-medium">Asset</th>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Identifier</th>
                <th className="px-5 py-3 font-medium">Scope</th>
                <th className="px-5 py-3 font-medium">Ownership</th>
                {isAdmin && <th className="px-5 py-3 font-medium">Scan</th>}
                {isAdmin && <th className="px-5 py-3 font-medium">Manual test</th>}
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => {
                const activeTest = tests.find(
                  (t) => t.assetId === asset.id && (t.status === "PLANNED" || t.status === "IN_PROGRESS")
                );
                const colSpan = isAdmin ? 7 : 5;
                return (
                  <Fragment key={asset.id}>
                    <tr className="border-b border-line-soft last:border-0">
                      <td className="px-5 py-3 font-medium text-ink">{asset.name}</td>
                      <td className="px-5 py-3 text-ink-soft">{asset.type}</td>
                      <td className="px-5 py-3 font-mono text-xs text-ink-soft">{asset.identifier}</td>
                      <td className="px-5 py-3">
                        <span
                          className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${
                            asset.inScope ? "bg-secure/10 text-secure" : "bg-line-soft text-ink-faint"
                          }`}
                        >
                          {asset.inScope ? "In scope" : "Excluded"}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <VerificationBadge asset={asset} />
                        {isAdmin && asset.verificationStatus !== "VERIFIED" && (
                          <button
                            className="ml-2 text-xs font-semibold text-ink underline decoration-dotted underline-offset-2"
                            onClick={() => setVerifyingAssetId(verifyingAssetId === asset.id ? null : asset.id)}
                          >
                            {verifyingAssetId === asset.id ? "Close" : "Verify"}
                          </button>
                        )}
                      </td>
                      {isAdmin && (
                        <td className="px-5 py-3">
                          <ScanCell
                            asset={asset}
                            job={scanJobs[asset.id]}
                            onScan={() => startScan(asset.id)}
                          />
                        </td>
                      )}
                      {isAdmin && (
                        <td className="px-5 py-3">
                          {!authorized ? (
                            <span className="text-xs text-ink-faint">Needs authorization</span>
                          ) : (
                            <button
                              className="text-xs font-semibold text-ink underline decoration-dotted underline-offset-2"
                              onClick={() => setManualTestAssetId(manualTestAssetId === asset.id ? null : asset.id)}
                            >
                              {manualTestAssetId === asset.id ? "Close" : activeTest ? "Resume" : "Start manual test"}
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                    {verifyingAssetId === asset.id && (
                      <tr className="border-b border-line-soft bg-paper/60">
                        <td colSpan={colSpan} className="px-5 py-4">
                          <VerifyPanel
                            engagementId={engagementId}
                            asset={asset}
                            onChanged={() => {
                              reload();
                            }}
                            onVerified={() => {
                              setVerifyingAssetId(null);
                              reload();
                            }}
                          />
                        </td>
                      </tr>
                    )}
                    {manualTestAssetId === asset.id && (
                      <tr className="border-b border-line-soft bg-paper/60">
                        <td colSpan={colSpan} className="px-5 py-4">
                          <ManualTestPanel
                            engagementId={engagementId}
                            asset={asset}
                            activeTest={activeTest}
                            onTestsChanged={reloadTests}
                            onCompleted={() => {
                              setManualTestAssetId(null);
                              reloadTests();
                            }}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function VerificationBadge({ asset }: { asset: Asset }) {
  if (asset.verificationStatus === "VERIFIED") {
    return (
      <Pill className="bg-secure/10 text-secure">
        Verified{asset.verificationMethod === "MANUAL" ? " (manual)" : ""}
      </Pill>
    );
  }
  if (asset.verificationStatus === "PENDING") {
    return <Pill className="bg-[color:var(--color-risk-medium)]/10 text-[color:var(--color-risk-medium)]">Pending</Pill>;
  }
  return <Pill className="bg-line-soft text-ink-faint">Unverified</Pill>;
}

function ScanCell({ asset, job, onScan }: { asset: Asset; job?: ScanJob; onScan: () => void }) {
  const scannable = SCANNABLE_TYPES.includes(asset.type) && asset.verificationStatus === "VERIFIED";

  if (job && (job.status === "QUEUED" || job.status === "RUNNING")) {
    return <span className="text-xs font-medium text-ink-soft">{job.status === "QUEUED" ? "Queued…" : "Scanning…"}</span>;
  }
  if (job && job.status === "FAILED") {
    return (
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-[color:var(--color-risk-critical)]" title={job.errorMessage ?? undefined}>
          Failed
        </span>
        {scannable && (
          <button className="text-xs font-semibold text-ink underline decoration-dotted underline-offset-2" onClick={onScan}>
            Retry
          </button>
        )}
      </div>
    );
  }
  if (job && job.status === "COMPLETE") {
    return (
      <div className="flex flex-col gap-1">
        <span className="text-xs text-ink-soft">
          {job.findingsCreated ?? 0} new · {job.findingsSkipped ?? 0} already open
        </span>
        {scannable && (
          <button className="text-left text-xs font-semibold text-ink underline decoration-dotted underline-offset-2" onClick={onScan}>
            Scan again
          </button>
        )}
      </div>
    );
  }
  if (!scannable) {
    return <span className="text-xs text-ink-faint">—</span>;
  }
  return (
    <button className="text-xs font-semibold text-ink underline decoration-dotted underline-offset-2" onClick={onScan}>
      Run scan
    </button>
  );
}

function VerifyPanel({
  engagementId,
  asset,
  onChanged,
  onVerified,
}: {
  engagementId: string;
  asset: Asset;
  onChanged: () => void;
  onVerified: () => void;
}) {
  const [instructions, setInstructions] = useState<{ method: VerificationMethod; token: string; instructions: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [checkResult, setCheckResult] = useState<"unknown" | "not-yet" | null>(null);
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function start(method: "DNS_TXT" | "HTTP_FILE") {
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<{ method: VerificationMethod; token: string; instructions: string }>(
        `/engagements/${engagementId}/assets/${asset.id}/verification/start`,
        { method }
      );
      setInstructions(res);
      setCheckResult(null);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't start verification.");
    } finally {
      setBusy(false);
    }
  }

  async function check() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<{ verified: boolean }>(`/engagements/${engagementId}/assets/${asset.id}/verification/check`);
      if (res.verified) onVerified();
      else setCheckResult("not-yet");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't check verification.");
    } finally {
      setBusy(false);
    }
  }

  async function submitManual(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post(`/engagements/${engagementId}/assets/${asset.id}/verification/manual`, { justification });
      onVerified();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't record manual verification.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-4 rounded-2xl border border-dashed border-line p-4">
      <p className="text-sm text-ink-soft">
        Prove control of <span className="font-mono text-ink">{asset.identifier}</span> before this asset can be
        automatically scanned — otherwise "scan this URL" would let anyone point Jupiter at a site they don't own.
      </p>

      {!instructions ? (
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={busy} onClick={() => start("DNS_TXT")}>
            Verify via DNS TXT record
          </Button>
          <Button variant="outline" disabled={busy} onClick={() => start("HTTP_FILE")}>
            Verify via HTTP file
          </Button>
        </div>
      ) : (
        <div className="flex flex-col gap-2 rounded-xl bg-line-soft p-3 text-sm">
          <p className="text-ink-soft">{instructions.instructions}</p>
          <code className="break-all rounded-lg bg-ink px-3 py-2 text-xs text-paper">{instructions.token}</code>
          <div className="flex items-center gap-3">
            <Button disabled={busy} onClick={check}>
              {busy ? "Checking…" : "I've published it — check now"}
            </Button>
            {checkResult === "not-yet" && <span className="text-xs text-ink-faint">Not found yet — DNS/CDN changes can take a few minutes to propagate.</span>}
          </div>
        </div>
      )}

      <details className="text-sm">
        <summary className="cursor-pointer font-medium text-ink-soft">
          This asset is already covered by our signed authorization (no DNS/HTTP proof needed)
        </summary>
        <form onSubmit={submitManual} className="mt-3 flex flex-col gap-2">
          <Field label="Justification">
            <textarea
              required
              minLength={10}
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className={inputClass}
              rows={2}
              placeholder="e.g. Covered by the signed ROE/SOW dated ... — internal infra the client already granted direct access to."
            />
          </Field>
          <div>
            <Button type="submit" variant="outline" disabled={busy}>
              Record manual verification
            </Button>
          </div>
        </form>
      </details>

      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
    </div>
  );
}

// Manual testing already worked through the app before this — log a test
// (Tests tab), then switch to the Findings tab and re-pick the same
// asset/test to record what you found. That's a lot of tab-hopping for
// "I'm sitting here running a manual pentest right now." This collapses it
// into one place: start (or resume) the test, log findings against it as
// you go without re-selecting anything, and mark it complete when done —
// all without leaving the asset row.
function ManualTestPanel({
  engagementId,
  asset,
  activeTest,
  onTestsChanged,
  onCompleted,
}: {
  engagementId: string;
  asset: Asset;
  activeTest?: Test;
  onTestsChanged: () => void;
  onCompleted: () => void;
}) {
  const [type, setType] = useState<TestType>("PENTEST");
  const [methodology, setMethodology] = useState("");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);

  function reloadFindings(testId: string) {
    setLoadingFindings(true);
    api
      .get<Finding[]>(`/engagements/${engagementId}/findings?testId=${testId}`)
      .then(setFindings)
      .finally(() => setLoadingFindings(false));
  }

  useEffect(() => {
    if (activeTest) reloadFindings(activeTest.id);
  }, [activeTest?.id]);

  async function handleStart(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setStarting(true);
    try {
      const test = await api.post<Test>(`/engagements/${engagementId}/tests`, {
        assetId: asset.id,
        type,
        methodology: methodology || undefined,
      });
      await api.patch(`/engagements/${engagementId}/tests/${test.id}`, { status: "IN_PROGRESS" });
      onTestsChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't start the test.");
    } finally {
      setStarting(false);
    }
  }

  async function handleComplete() {
    if (!activeTest) return;
    await api.patch(`/engagements/${engagementId}/tests/${activeTest.id}`, { status: "COMPLETE" });
    onCompleted();
  }

  if (!activeTest) {
    return (
      <form onSubmit={handleStart} className="flex flex-col gap-4 rounded-2xl border border-dashed border-line p-4">
        <p className="text-sm text-ink-soft">
          Start a manual test against <span className="font-medium text-ink">{asset.name}</span> — findings you log
          below land immediately, no separate test/asset selection needed.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Test type">
            <select value={type} onChange={(e) => setType(e.target.value as TestType)} className={inputClass}>
              {MANUAL_TEST_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Methodology / tool (optional)">
            <input
              value={methodology}
              onChange={(e) => setMethodology(e.target.value)}
              className={inputClass}
              placeholder="OWASP Testing Guide, Burp Suite…"
            />
          </Field>
        </div>
        {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
        <div>
          <Button type="submit" disabled={starting}>
            {starting ? "Starting…" : "Start manual test"}
          </Button>
        </div>
      </form>
    );
  }

  return (
    <div className="flex flex-col gap-4 rounded-2xl border border-dashed border-line p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm text-ink-soft">
          <span className="font-medium text-ink">{activeTest.type.replace(/_/g, " ")}</span> in progress on{" "}
          <span className="font-medium text-ink">{asset.name}</span>
          {activeTest.toolUsed && ` — ${activeTest.toolUsed}`}
        </p>
        <Button variant="outline" onClick={handleComplete} className="!py-1.5 text-xs">
          Mark test complete
        </Button>
      </div>

      {loadingFindings ? (
        <div className="h-8 animate-pulse rounded-lg bg-line-soft" />
      ) : findings.length > 0 ? (
        <ul className="flex flex-col gap-1.5">
          {findings.map((f) => (
            <li key={f.id} className="flex items-center gap-2.5 rounded-xl bg-line-soft px-3 py-2 text-sm">
              <SeverityBadge severity={f.severity} />
              <span className="truncate text-ink">{f.title}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-ink-faint">No findings logged for this test yet.</p>
      )}

      <ManualFindingForm
        engagementId={engagementId}
        testId={activeTest.id}
        assetId={asset.id}
        onCreated={() => reloadFindings(activeTest.id)}
      />
    </div>
  );
}

function ManualFindingForm({
  engagementId,
  testId,
  assetId,
  onCreated,
}: {
  engagementId: string;
  testId: string;
  assetId: string;
  onCreated: () => void;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("MEDIUM");
  const [reproductionSteps, setReproductionSteps] = useState("");
  const [remediationGuidance, setRemediationGuidance] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/engagements/${engagementId}/tests/${testId}/findings`, {
        assetId,
        title,
        description,
        severity,
        reproductionSteps: reproductionSteps || undefined,
        remediationGuidance: remediationGuidance || undefined,
      });
      setTitle("");
      setDescription("");
      setReproductionSteps("");
      setRemediationGuidance("");
      setSeverity("MEDIUM");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't log the finding.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3 border-t border-line-soft pt-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
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
      </div>
      <Field label="Description (encrypted at rest)">
        <textarea required value={description} onChange={(e) => setDescription(e.target.value)} className={`${inputClass} min-h-16`} />
      </Field>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="Reproduction steps (encrypted at rest)">
          <textarea value={reproductionSteps} onChange={(e) => setReproductionSteps(e.target.value)} className={`${inputClass} min-h-14`} />
        </Field>
        <Field label="Remediation guidance (encrypted at rest)">
          <textarea value={remediationGuidance} onChange={(e) => setRemediationGuidance(e.target.value)} className={`${inputClass} min-h-14`} />
        </Field>
      </div>
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div>
        <Button type="submit" variant="outline" disabled={submitting}>
          {submitting ? "Logging…" : "+ Log finding"}
        </Button>
      </div>
    </form>
  );
}

function NewAssetForm({ engagementId, onCreated }: { engagementId: string; onCreated: () => void }) {
  const [type, setType] = useState<AssetType>("WEB");
  const [name, setName] = useState("");
  const [identifier, setIdentifier] = useState("");
  const [criticality, setCriticality] = useState<Criticality>("MEDIUM");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/engagements/${engagementId}/assets`, { type, name, identifier, criticality });
      setName("");
      setIdentifier("");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't add the asset.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-4">
      <Field label="Name">
        <input required value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Customer portal" />
      </Field>
      <Field label="Type">
        <select value={type} onChange={(e) => setType(e.target.value as AssetType)} className={inputClass}>
          {ASSET_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Identifier (encrypted at rest)">
        <input
          required
          value={identifier}
          onChange={(e) => setIdentifier(e.target.value)}
          className={inputClass}
          placeholder="https://app.acme.com or 10.0.4.12"
        />
      </Field>
      <Field label="Criticality">
        <select value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality)} className={inputClass}>
          {CRITICALITIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </Field>
      {error && <p className="sm:col-span-4 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div className="sm:col-span-4">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Adding…" : "Add asset"}
        </Button>
      </div>
    </form>
  );
}

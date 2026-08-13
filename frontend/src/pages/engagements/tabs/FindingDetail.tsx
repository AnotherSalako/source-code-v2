import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { uploadEvidenceDirect } from "../../../lib/evidenceUpload";
import { useAuth } from "../../../lib/auth";
import type { Evidence, Finding, FindingStatus, MalwareStatus, RemediationEffort, Retest, RetestResult } from "../../../lib/types";
import { Button, Field, inputClass, Pill } from "../../../components/ui";
import { EncryptedField } from "../../../components/EncryptedField";
import { SeverityBadge, StatusPill } from "../../../components/Severity";

const FINDING_STATUSES: FindingStatus[] = ["OPEN", "REMEDIATING", "RETESTED_PASS", "RETESTED_FAIL", "ACCEPTED_RISK"];
const RETEST_RESULTS: RetestResult[] = ["FIXED", "NOT_FIXED", "PARTIALLY_FIXED"];
const EFFORT_OPTIONS: RemediationEffort[] = ["QUICK_WIN", "SMALL", "MEDIUM", "LARGE"];

export function FindingDetail({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const canSeeEvidence = user?.role !== "EXEC_CLIENT";

  const [finding, setFinding] = useState<Finding | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [retests, setRetests] = useState<Retest[]>([]);
  const [loading, setLoading] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [containing, setContaining] = useState(false);
  const [containResult, setContainResult] = useState<{ success: boolean; message: string } | null>(null);

  function reload() {
    setLoading(true);
    const calls: Promise<unknown>[] = [
      api.get<Finding>(`/findings/${findingId}`).then(setFinding),
      api.get<Retest[]>(`/findings/${findingId}/retest-history`).then(setRetests),
    ];
    if (canSeeEvidence) {
      calls.push(api.get<Evidence[]>(`/findings/${findingId}/evidence`).then(setEvidence));
    }
    Promise.all(calls).finally(() => setLoading(false));
  }

  useEffect(reload, [findingId]);

  async function handleStatusChange(status: FindingStatus) {
    await api.patch(`/findings/${findingId}`, { status });
    reload();
  }

  async function handleEffortChange(remediationEffort: RemediationEffort) {
    await api.patch(`/findings/${findingId}`, { remediationEffort });
    reload();
  }

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      // Direct-to-storage first — bypasses this app's own backend for the
      // file bytes entirely, the only way past Vercel's request-body limit
      // for large evidence (screen recordings, pcaps). Falls back to the
      // regular multipart route when the storage backend doesn't support it
      // (local dev), so this works either way without the caller caring.
      const wentDirect = await uploadEvidenceDirect(findingId, file);
      if (!wentDirect) {
        await api.upload(`/findings/${findingId}/evidence`, file);
      }
      reload();
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function handleContain() {
    setContaining(true);
    setContainResult(null);
    try {
      const result = await api.post<{ success: boolean; message: string }>(`/findings/${findingId}/response-actions/contain`);
      setContainResult(result);
    } catch (err) {
      setContainResult({ success: false, message: err instanceof ApiError ? err.message : "Request failed." });
    } finally {
      setContaining(false);
    }
  }

  async function handleDownload(item: Evidence) {
    const blob = await api.downloadBlob(`/findings/${findingId}/evidence/${item.id}`);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = item.originalFilename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="fixed inset-0 z-20 flex items-stretch justify-end bg-ink/30 backdrop-blur-sm" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-lg flex-col gap-6 overflow-y-auto border-l border-line bg-surface p-6 shadow-[var(--shadow-lift-lg)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            {finding && <SeverityBadge severity={finding.severity} />}
            <h2 className="mt-2 text-lg font-bold text-ink">{finding?.title ?? "Loading…"}</h2>
          </div>
          <button onClick={onClose} className="rounded-full p-1.5 text-ink-faint hover:bg-line-soft hover:text-ink" aria-label="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
              <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        {loading || !finding ? (
          <div className="flex flex-col gap-3">
            <div className="h-4 w-1/2 animate-pulse rounded bg-line-soft" />
            <div className="h-16 animate-pulse rounded bg-line-soft" />
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-3">
              <StatusPill status={finding.status} />
              {isAdmin && (
                <select
                  value={finding.status}
                  onChange={(e) => handleStatusChange(e.target.value as FindingStatus)}
                  className={`${inputClass} !py-1.5 text-xs`}
                >
                  {FINDING_STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {s.replace(/_/g, " ")}
                    </option>
                  ))}
                </select>
              )}
              {isAdmin && (
                <select
                  value={finding.remediationEffort ?? ""}
                  onChange={(e) => handleEffortChange(e.target.value as RemediationEffort)}
                  className={`${inputClass} !py-1.5 text-xs`}
                >
                  <option value="" disabled>
                    Remediation effort
                  </option>
                  {EFFORT_OPTIONS.map((e) => (
                    <option key={e} value={e}>
                      {e.replace("_", " ")}
                    </option>
                  ))}
                </select>
              )}
              {isAdmin && (
                <Button variant="outline" onClick={handleContain} disabled={containing} className="!py-1.5 text-xs">
                  {containing ? "Requesting…" : "Attempt containment"}
                </Button>
              )}
            </div>

            {containResult && (
              <p
                className={`text-sm ${
                  containResult.success ? "text-secure" : "text-ink-faint"
                }`}
              >
                {containResult.message}
              </p>
            )}

            {finding.description !== undefined && (
              <div className="flex flex-col gap-4 border-t border-line-soft pt-5">
                <EncryptedField label="Description" value={finding.description} />
                <EncryptedField label="Reproduction steps" value={finding.reproductionSteps} />
                <EncryptedField label="Remediation guidance" value={finding.remediationGuidance} />
              </div>
            )}

            {canSeeEvidence && (
              <div className="border-t border-line-soft pt-5">
                <div className="mb-3 flex items-center justify-between">
                  <p className="text-xs font-semibold uppercase tracking-[0.1em] text-ink-faint">Evidence</p>
                  {isAdmin && (
                    <label className="cursor-pointer text-xs font-semibold text-ink-soft hover:text-ink">
                      {uploading ? "Uploading…" : "+ Upload file"}
                      <input ref={fileInputRef} type="file" onChange={handleUpload} className="hidden" disabled={uploading} />
                    </label>
                  )}
                </div>
                {evidence.length === 0 ? (
                  <p className="text-sm text-ink-faint">No evidence attached yet.</p>
                ) : (
                  <ul className="flex flex-col gap-1.5">
                    {evidence.map((item) => (
                      <li key={item.id}>
                        <button
                          onClick={() => handleDownload(item)}
                          className="flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2 text-left text-sm transition-colors hover:bg-line-soft"
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <span className="truncate text-ink">{item.originalFilename}</span>
                            <MalwareBadge status={item.malwareStatus} detections={item.malwareDetections} />
                          </span>
                          <span className="shrink-0 text-xs text-ink-faint">{(item.sizeBytes / 1024).toFixed(0)} KB ↓</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            <div className="border-t border-line-soft pt-5">
              <p className="mb-3 text-xs font-semibold uppercase tracking-[0.1em] text-ink-faint">Retest history</p>
              {retests.length === 0 ? (
                <p className="text-sm text-ink-faint">Not retested yet.</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {retests.map((r) => (
                    <li key={r.id} className="flex items-center justify-between rounded-xl bg-paper px-3 py-2 text-sm">
                      <span className="text-ink">{r.result.replace(/_/g, " ").toLowerCase()}</span>
                      <span className="text-xs text-ink-faint">{new Date(r.retestedAt).toLocaleDateString()}</span>
                    </li>
                  ))}
                </ul>
              )}
              {isAdmin && <RetestForm findingId={findingId} onCreated={reload} />}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function MalwareBadge({ status, detections }: { status: MalwareStatus; detections: number | null }) {
  if (status === "PENDING") return <Pill className="bg-line-soft text-ink-faint">Checking…</Pill>;
  if (status === "UNAVAILABLE") return null; // no verdict — don't clutter the row with a non-signal
  if (status === "FLAGGED") {
    return (
      <Pill className="bg-[color:var(--color-risk-critical)]/10 text-[color:var(--color-risk-critical)]">
        Flagged{detections ? ` (${detections})` : ""}
      </Pill>
    );
  }
  return <Pill className="bg-secure/10 text-secure">Clean</Pill>;
}

function RetestForm({ findingId, onCreated }: { findingId: string; onCreated: () => void }) {
  const [result, setResult] = useState<RetestResult>("FIXED");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/findings/${findingId}/retest`, { result, notes: notes || undefined });
      setNotes("");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't record the retest.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="mt-3 flex flex-col gap-2.5">
      <div className="flex gap-2">
        <select value={result} onChange={(e) => setResult(e.target.value as RetestResult)} className={`${inputClass} flex-1`}>
          {RETEST_RESULTS.map((r) => (
            <option key={r} value={r}>
              {r.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </div>
      <Field label="Notes (encrypted at rest)">
        <input value={notes} onChange={(e) => setNotes(e.target.value)} className={inputClass} placeholder="What was verified" />
      </Field>
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <Button type="submit" variant="outline" disabled={submitting} className="self-start">
        {submitting ? "Recording…" : "Record retest"}
      </Button>
    </form>
  );
}

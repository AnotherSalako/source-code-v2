import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../../lib/api";
import type { Client } from "../../lib/types";
import { Button, Card, inputClass } from "../../components/ui";

interface DeletionResult {
  deletedCounts: Record<string, number>;
  storageKeysDeleted: number;
  storageKeysFailed: number;
}

// Self-service data erasure ("right to be forgotten") — the counterpart to
// DELETE /clients/:id in clients.routes.ts. Type-to-confirm against the
// client's real name (same pattern GitHub/Vercel use for destroying a
// repo/project) so this can't be triggered by a stray click, matching what
// the backend itself requires in the request body.
export function DeleteClientSection({ client }: { client: Client }) {
  const navigate = useNavigate();
  const [confirmName, setConfirmName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DeletionResult | null>(null);

  const matches = confirmName.trim() === client.name;

  async function handleDelete() {
    if (!matches) return;
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.delete<DeletionResult>(`/clients/${client.id}`, { confirmName });
      setResult(res);
      // Give them a moment to read the confirmation before the record they're
      // standing on disappears out from under them.
      setTimeout(() => navigate("/clients"), 2500);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't delete this client's data.");
      setSubmitting(false);
    }
  }

  if (result) {
    const totalRows = Object.values(result.deletedCounts).reduce((sum, n) => sum + n, 0);
    return (
      <Card className="border-secure/30 bg-secure/5">
        <p className="text-sm font-semibold text-secure">Data erased</p>
        <p className="mt-1 text-sm text-ink-soft">
          Permanently deleted {totalRows} record{totalRows === 1 ? "" : "s"} and {result.storageKeysDeleted} stored file
          {result.storageKeysDeleted === 1 ? "" : "s"} for {client.name}.
          {result.storageKeysFailed > 0 && ` (${result.storageKeysFailed} file(s) failed to delete — check server logs.)`}
        </p>
        <p className="mt-2 text-xs text-ink-faint">Redirecting…</p>
      </Card>
    );
  }

  return (
    <Card className="border-[color:var(--color-risk-critical)]/30">
      <p className="text-xs font-semibold uppercase tracking-[0.1em] text-[color:var(--color-risk-critical)]">Danger zone</p>
      <p className="mt-2 text-sm font-semibold text-ink">Permanently delete all data for {client.name}</p>
      <p className="mt-1 max-w-xl text-sm text-ink-faint">
        Erases every engagement, asset, finding, evidence file, report, compliance check, and training session for this
        client, plus every user account scoped to this org — including yours, if you're a client-side user. This cannot
        be undone. Enforcer's own accountability audit log is kept, as required for our records.
      </p>
      <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
        <label className="flex flex-1 flex-col gap-1.5 text-sm">
          <span className="font-medium text-ink-soft">
            Type <span className="font-mono text-ink">{client.name}</span> to confirm
          </span>
          <input
            value={confirmName}
            onChange={(e) => setConfirmName(e.target.value)}
            className={inputClass}
            placeholder={client.name}
            autoComplete="off"
          />
        </label>
        <Button
          onClick={handleDelete}
          disabled={!matches || submitting}
          className="!bg-[color:var(--color-risk-critical)] text-white hover:!bg-[color:var(--color-risk-critical)]/90"
        >
          {submitting ? "Deleting…" : "Delete permanently"}
        </Button>
      </div>
      {error && <p className="mt-3 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
    </Card>
  );
}

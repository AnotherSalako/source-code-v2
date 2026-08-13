import { useRef, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { Engagement } from "../../../lib/types";
import { Button, Card, Field, inputClass, SectionLabel } from "../../../components/ui";
import { EncryptedField } from "../../../components/EncryptedField";
import { StageTracker } from "./StageTracker";

export function OverviewTab({ engagement, onUpdated }: { engagement: Engagement; onUpdated: () => void }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const authorized = Boolean(engagement.authorizationSignedAt);

  return (
    <div className="flex flex-col gap-5">
      <StageTracker engagement={engagement} />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card className="flex flex-col gap-5">
          <SectionLabel>Scope</SectionLabel>
          <EncryptedField label="Assumptions" value={engagement.assumptions || undefined} />
          <EncryptedField label="Exclusions" value={engagement.exclusions || undefined} />
          {isAdmin && <ScopeForm engagement={engagement} onUpdated={onUpdated} />}
        </Card>

        <Card className="flex flex-col gap-4">
          <SectionLabel>Authorization</SectionLabel>
          {authorized ? (
            <div className="flex flex-col gap-1.5">
              <p className="text-sm text-ink">
                Signed off by <span className="font-semibold">{engagement.authorizedBy}</span>
              </p>
              <p className="text-xs text-ink-faint">
                {new Date(engagement.authorizationSignedAt!).toLocaleString(undefined, {
                  dateStyle: "long",
                  timeStyle: "short",
                })}
              </p>
              <p className="mt-3 rounded-2xl bg-secure/10 px-4 py-3 text-sm text-secure">
                Testing is authorized. Tests and findings can now be logged for this engagement.
              </p>
            </div>
          ) : isAdmin ? (
            <AuthorizationPanel engagement={engagement} onUpdated={onUpdated} />
          ) : (
            <p className="rounded-2xl bg-[color:var(--color-risk-critical)]/10 px-4 py-3 text-sm text-[color:var(--color-risk-critical)]">
              This engagement has not been authorized yet. No testing has started.
            </p>
          )}
        </Card>
      </div>
    </div>
  );
}

function ScopeForm({ engagement, onUpdated }: { engagement: Engagement; onUpdated: () => void }) {
  const [assumptions, setAssumptions] = useState(engagement.assumptions ?? "");
  const [exclusions, setExclusions] = useState(engagement.exclusions ?? "");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.patch(`/engagements/${engagement.id}/scope`, {
        assumptions: assumptions || undefined,
        exclusions: exclusions || undefined,
      });
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't update scope.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3 border-t border-line-soft pt-4">
      <Field label="Update assumptions">
        <textarea value={assumptions} onChange={(e) => setAssumptions(e.target.value)} className={`${inputClass} min-h-16`} />
      </Field>
      <Field label="Update exclusions">
        <textarea value={exclusions} onChange={(e) => setExclusions(e.target.value)} className={`${inputClass} min-h-16`} />
      </Field>
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <Button type="submit" variant="outline" disabled={submitting} className="self-start">
        {submitting ? "Saving…" : "Save scope"}
      </Button>
    </form>
  );
}

function AuthorizationPanel({ engagement, onUpdated }: { engagement: Engagement; onUpdated: () => void }) {
  const [mode, setMode] = useState<"manual" | "esignature">(engagement.authorizationEnvelopeId ? "esignature" : "manual");

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-ink-faint">
        Record the signed rules-of-engagement before any testing starts. This is a hard gate — no test or finding can be
        created until this is on file.
      </p>
      <div className="flex gap-1 rounded-full bg-line-soft p-1 text-xs font-semibold">
        <button
          type="button"
          onClick={() => setMode("manual")}
          className={`flex-1 rounded-full px-3 py-1.5 transition-colors ${mode === "manual" ? "bg-surface text-ink shadow-sm" : "text-ink-faint"}`}
        >
          Manual
        </button>
        <button
          type="button"
          onClick={() => setMode("esignature")}
          className={`flex-1 rounded-full px-3 py-1.5 transition-colors ${mode === "esignature" ? "bg-surface text-ink shadow-sm" : "text-ink-faint"}`}
        >
          E-signature
        </button>
      </div>
      {mode === "manual" ? (
        <AuthorizeForm engagementId={engagement.id} onUpdated={onUpdated} />
      ) : (
        <ESignatureAuthorization engagement={engagement} onUpdated={onUpdated} />
      )}
    </div>
  );
}

function AuthorizeForm({ engagementId, onUpdated }: { engagementId: string; onUpdated: () => void }) {
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [authorizationDocRef, setAuthorizationDocRef] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/engagements/${engagementId}/authorize`, { authorizedBy, authorizationDocRef });
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't record authorization.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <p className="text-xs text-ink-faint">Self-attested — you're vouching that a signed copy exists outside this system.</p>
      <Field label="Signed by (name, title)">
        <input
          required
          value={authorizedBy}
          onChange={(e) => setAuthorizedBy(e.target.value)}
          className={inputClass}
          placeholder="Jane Doe, CTO"
        />
      </Field>
      <Field label="Signed document reference">
        <input
          required
          value={authorizationDocRef}
          onChange={(e) => setAuthorizationDocRef(e.target.value)}
          className={inputClass}
          placeholder="storage key or file reference"
        />
      </Field>
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <Button type="submit" disabled={submitting} className="self-start">
        {submitting ? "Recording…" : "Mark as authorized"}
      </Button>
    </form>
  );
}

function ESignatureAuthorization({ engagement, onUpdated }: { engagement: Engagement; onUpdated: () => void }) {
  const [signerEmail, setSignerEmail] = useState("");
  const [signerName, setSignerName] = useState("");
  const [sending, setSending] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [signingUrl, setSigningUrl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleSend(e: FormEvent) {
    e.preventDefault();
    const file = fileInputRef.current?.files?.[0];
    if (!file) {
      setError("Attach the ROE/authorization PDF to send.");
      return;
    }
    setError(null);
    setSending(true);
    try {
      const result = await api.upload<{ signingUrl?: string }>(
        `/engagements/${engagement.id}/authorize/send`,
        file,
        { signerEmail, signerName }
      );
      setSigningUrl(result.signingUrl ?? null);
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't send for signature.");
    } finally {
      setSending(false);
    }
  }

  async function handleCheck() {
    setChecking(true);
    setError(null);
    try {
      await api.post(`/engagements/${engagement.id}/authorize/check`);
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't check signature status.");
    } finally {
      setChecking(false);
    }
  }

  if (engagement.authorizationEnvelopeId) {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-ink">
          Sent to <span className="font-semibold">{engagement.authorizedBy}</span> for signature.
        </p>
        <p className="text-xs text-ink-faint">
          Status: {engagement.authorizationRequestStatus?.toLowerCase() ?? "sent"} — the gate only opens once the
          provider itself confirms it's signed, not on send.
        </p>
        {signingUrl && (
          <a href={signingUrl} target="_blank" rel="noreferrer" className="text-xs font-semibold text-ink underline">
            Open signing link
          </a>
        )}
        <Button variant="outline" onClick={handleCheck} disabled={checking} className="self-start">
          {checking ? "Checking…" : "Check signature status"}
        </Button>
        {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      </div>
    );
  }

  return (
    <form onSubmit={handleSend} className="flex flex-col gap-3">
      <p className="text-xs text-ink-faint">
        Sends the ROE out through a real e-signature provider — the gate opens only once that provider confirms it's
        actually signed, not on your say-so. Requires <code>ESIGNATURE_PROVIDER</code> configured server-side.
      </p>
      <Field label="ROE / authorization PDF">
        <input ref={fileInputRef} type="file" accept="application/pdf" required className={inputClass} />
      </Field>
      <Field label="Signer name">
        <input required value={signerName} onChange={(e) => setSignerName(e.target.value)} className={inputClass} placeholder="Jane Doe, CTO" />
      </Field>
      <Field label="Signer email">
        <input
          required
          type="email"
          value={signerEmail}
          onChange={(e) => setSignerEmail(e.target.value)}
          className={inputClass}
          placeholder="jane@client.com"
        />
      </Field>
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <Button type="submit" disabled={sending} className="self-start">
        {sending ? "Sending…" : "Send for signature"}
      </Button>
    </form>
  );
}

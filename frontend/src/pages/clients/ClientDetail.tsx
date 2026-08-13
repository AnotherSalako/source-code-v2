import { useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import type { Client, Engagement } from "../../lib/types";
import { TopBar } from "../../components/TopBar";
import { Button, Card, EmptyState, Field, inputClass } from "../../components/ui";
import { FindingsTrend } from "./FindingsTrend";
import { DeleteClientSection } from "./DeleteClientSection";

export default function ClientDetail() {
  const { clientId } = useParams<{ clientId: string }>();
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  // Mirrors the backend RBAC in clients.routes.ts's DELETE /:id: an EXEC_CLIENT
  // may erase their own org's data (self-service), SECURITY_ADMIN may erase
  // any org's on their behalf, TECHNICAL_CLIENT cannot — this is an
  // account-level decision, not a working-technical-contact one.
  const canDeleteClient = isAdmin || (user?.role === "EXEC_CLIENT" && user.orgId === clientId);
  const [client, setClient] = useState<Client | null>(null);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  function reload() {
    if (!clientId) return;
    setLoading(true);
    Promise.all([
      api.get<Client>(`/clients/${clientId}`),
      api.get<Engagement[]>(`/engagements?clientId=${clientId}`),
    ])
      .then(([c, e]) => {
        setClient(c);
        setEngagements(e);
      })
      .finally(() => setLoading(false));
  }

  useEffect(reload, [clientId]);

  if (loading) {
    return <div className="h-48 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />;
  }
  if (!client) {
    return <EmptyState title="Client not found" hint="It may have been removed, or you don't have access to it." />;
  }

  return (
    <>
      <TopBar
        title={client.name}
        subtitle={client.industry ?? "Industry not set"}
        actions={isAdmin && <Button onClick={() => setShowForm((s) => !s)}>{showForm ? "Cancel" : "+ New engagement"}</Button>}
      />

      {client.primaryContact && (
        <Card className="max-w-md">
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-[0.1em] text-ink-faint">Primary contact</p>
          <p className="text-sm text-ink">{client.primaryContact}</p>
        </Card>
      )}

      <FindingsTrend clientId={client.id} />

      {showForm && (
        <Card>
          <NewEngagementForm
            clientId={client.id}
            onCreated={() => {
              setShowForm(false);
              reload();
            }}
          />
        </Card>
      )}

      <div>
        <p className="mb-4 text-sm font-medium text-ink-soft">Engagements</p>
        {engagements.length === 0 ? (
          <EmptyState title="No engagements yet" hint="Start one to begin scoping this client's assessment." />
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {engagements.map((eng) => (
              <Link
                key={eng.id}
                to={`/engagements/${eng.id}`}
                className="flex flex-col gap-3 rounded-[var(--radius-card)] border border-line bg-surface/90 p-5 shadow-[var(--shadow-lift)] backdrop-blur-xl transition-transform hover:-translate-y-0.5"
              >
                <span
                  className={`self-start inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${
                    eng.authorizationSignedAt ? "bg-secure/10 text-secure" : "bg-[color:var(--color-risk-critical)]/10 text-[color:var(--color-risk-critical)]"
                  }`}
                >
                  {eng.authorizationSignedAt ? "Authorized" : "Not authorized"}
                </span>
                <p className="text-sm font-semibold text-ink">
                  {eng.status.charAt(0) + eng.status.slice(1).toLowerCase()}
                </p>
                <p className="text-xs text-ink-faint">
                  Opened {new Date(eng.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
                </p>
              </Link>
            ))}
          </div>
        )}
      </div>

      {canDeleteClient && <DeleteClientSection client={client} />}
    </>
  );
}

function NewEngagementForm({ clientId, onCreated }: { clientId: string; onCreated: () => void }) {
  const [assumptions, setAssumptions] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post("/engagements", { clientId, assumptions: assumptions || undefined, exclusions: exclusions || undefined });
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't create the engagement.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Field label="Assumptions (encrypted at rest)">
        <textarea
          value={assumptions}
          onChange={(e) => setAssumptions(e.target.value)}
          className={`${inputClass} min-h-20`}
          placeholder="e.g. Staging environment mirrors production; no load testing"
        />
      </Field>
      <Field label="Exclusions (encrypted at rest)">
        <textarea
          value={exclusions}
          onChange={(e) => setExclusions(e.target.value)}
          className={`${inputClass} min-h-20`}
          placeholder="e.g. Third-party payment processor is out of scope"
        />
      </Field>
      {error && <p className="text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div>
        <Button type="submit" disabled={submitting}>
          {submitting ? "Creating…" : "Create engagement"}
        </Button>
      </div>
    </form>
  );
}

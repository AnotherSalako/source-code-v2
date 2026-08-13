import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import type { Client } from "../../lib/types";
import { TopBar } from "../../components/TopBar";
import { Button, Card, EmptyState, Field, inputClass } from "../../components/ui";

export default function ClientsList() {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  function reload() {
    setLoading(true);
    api
      .get<Client[]>("/clients")
      .then(setClients)
      .finally(() => setLoading(false));
  }

  useEffect(reload, []);

  return (
    <>
      <TopBar
        title="Clients"
        subtitle={isAdmin ? `${clients.length} client${clients.length === 1 ? "" : "s"} on file` : "Your organization"}
        actions={isAdmin && <Button onClick={() => setShowForm((s) => !s)}>{showForm ? "Cancel" : "+ Add client"}</Button>}
      />

      {showForm && (
        <Card>
          <NewClientForm
            onCreated={() => {
              setShowForm(false);
              reload();
            }}
          />
        </Card>
      )}

      {loading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-32 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
          ))}
        </div>
      ) : clients.length === 0 ? (
        <EmptyState title="No clients yet" hint="Add the first client to start scoping an engagement." />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {clients.map((client) => (
            <Link
              key={client.id}
              to={`/clients/${client.id}`}
              className="flex flex-col gap-2 rounded-[var(--radius-card)] border border-line bg-surface/90 p-5 shadow-[var(--shadow-lift)] backdrop-blur-xl transition-transform hover:-translate-y-0.5"
            >
              <p className="font-semibold text-ink">{client.name}</p>
              <p className="text-sm text-ink-faint">{client.industry ?? "Industry not set"}</p>
              <p className="mt-2 text-xs text-ink-faint">
                Added {new Date(client.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
              </p>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

function NewClientForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [primaryContact, setPrimaryContact] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post("/clients", { name, industry: industry || undefined, primaryContact: primaryContact || undefined });
      setName("");
      setIndustry("");
      setPrimaryContact("");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't create the client.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      <Field label="Company name">
        <input required value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Acme Ltd" />
      </Field>
      <Field label="Industry">
        <input value={industry} onChange={(e) => setIndustry(e.target.value)} className={inputClass} placeholder="Fintech" />
      </Field>
      <Field label="Primary contact (encrypted at rest)">
        <input
          value={primaryContact}
          onChange={(e) => setPrimaryContact(e.target.value)}
          className={inputClass}
          placeholder="name, email, phone"
        />
      </Field>
      {error && <p className="sm:col-span-3 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div className="sm:col-span-3">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Adding…" : "Add client"}
        </Button>
      </div>
    </form>
  );
}

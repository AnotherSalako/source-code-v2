import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../../lib/api";
import type { Client, Role, TeamMember } from "../../lib/types";
import { TopBar } from "../../components/TopBar";
import { Button, Card, EmptyState, Field, inputClass } from "../../components/ui";

const ROLES: Role[] = ["SECURITY_ADMIN", "TECHNICAL_CLIENT", "EXEC_CLIENT"];
const ROLE_LABEL: Record<Role, string> = {
  SECURITY_ADMIN: "Security admin",
  TECHNICAL_CLIENT: "Technical (client)",
  EXEC_CLIENT: "Executive (client)",
};

export default function Team() {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  function reload() {
    setLoading(true);
    Promise.all([api.get<TeamMember[]>("/users"), api.get<Client[]>("/clients")])
      .then(([m, c]) => {
        setMembers(m);
        setClients(c);
      })
      .finally(() => setLoading(false));
  }

  useEffect(reload, []);

  async function handleRemove(member: TeamMember) {
    if (!confirm(`Remove ${member.name} (${member.email})? They'll lose access to Jupiter immediately.`)) return;
    await api.delete(`/users/${member.id}`);
    reload();
  }

  return (
    <>
      <TopBar
        title="Team"
        subtitle="Sign-up is invite-only — adding someone here creates their access record and sends a real Clerk invitation email."
        actions={<Button onClick={() => setShowForm((s) => !s)}>{showForm ? "Cancel" : "+ Invite"}</Button>}
      />

      {showForm && (
        <Card>
          <InviteForm
            clients={clients}
            onCreated={() => {
              setShowForm(false);
              reload();
            }}
          />
        </Card>
      )}

      {loading ? (
        <div className="h-48 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
      ) : members.length === 0 ? (
        <EmptyState title="No team members yet" />
      ) : (
        <Card className="overflow-hidden !p-0">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-line-soft text-xs uppercase tracking-wide text-ink-faint">
                <th className="px-5 py-3 font-medium">Name</th>
                <th className="px-5 py-3 font-medium">Email</th>
                <th className="px-5 py-3 font-medium">Role</th>
                <th className="px-5 py-3 font-medium">Org</th>
                <th className="px-5 py-3 font-medium">Last login</th>
                <th className="px-5 py-3 font-medium" />
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.id} className="border-b border-line-soft last:border-0">
                  <td className="px-5 py-3 font-medium text-ink">{m.name}</td>
                  <td className="px-5 py-3 font-mono text-xs text-ink-soft">{m.email}</td>
                  <td className="px-5 py-3 text-ink-soft">{ROLE_LABEL[m.role]}</td>
                  <td className="px-5 py-3 text-ink-soft">{clients.find((c) => c.id === m.orgId)?.name ?? "—"}</td>
                  <td className="px-5 py-3 text-xs text-ink-faint">
                    {m.lastLoginAt ? new Date(m.lastLoginAt).toLocaleDateString() : "Never signed in"}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <button
                      onClick={() => handleRemove(m)}
                      className="text-xs font-semibold text-[color:var(--color-risk-critical)] underline decoration-dotted underline-offset-2"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </>
  );
}

function InviteForm({ clients, onCreated }: { clients: Client[]; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("SECURITY_ADMIN");
  const [orgId, setOrgId] = useState(clients[0]?.id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setSubmitting(true);
    try {
      const res = await api.post<{ invitationSent: boolean; invitationError?: string }>("/users", {
        name,
        email,
        role,
        orgId: role === "SECURITY_ADMIN" ? undefined : orgId,
      });
      setResult(
        res.invitationSent
          ? `Invitation sent to ${email}.`
          : `Access record created, but the Clerk invitation failed to send (${res.invitationError}). They won't be able to sign in until that's resolved.`
      );
      setName("");
      setEmail("");
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't add this person.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-4">
      <Field label="Name">
        <input required value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Jane Doe" />
      </Field>
      <Field label="Email">
        <input
          required
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className={inputClass}
          placeholder="jane@example.com"
        />
      </Field>
      <Field label="Role">
        <select value={role} onChange={(e) => setRole(e.target.value as Role)} className={inputClass}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {ROLE_LABEL[r]}
            </option>
          ))}
        </select>
      </Field>
      {role !== "SECURITY_ADMIN" && (
        <Field label="Client org">
          <select value={orgId} onChange={(e) => setOrgId(e.target.value)} className={inputClass}>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </Field>
      )}
      {error && <p className="sm:col-span-4 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      {result && <p className="sm:col-span-4 text-sm text-secure">{result}</p>}
      <div className="sm:col-span-4">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Sending invite…" : "Send invite"}
        </Button>
      </div>
    </form>
  );
}

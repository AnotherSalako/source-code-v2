import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "../../../lib/api";
import { useAuth } from "../../../lib/auth";
import type { TrainingSession, TrainingStatus, TrainingTopic } from "../../../lib/types";
import { Button, Card, EmptyState, Field, inputClass } from "../../../components/ui";

const TOPICS: { value: TrainingTopic; label: string }[] = [
  { value: "PHISHING", label: "Phishing awareness" },
  { value: "PASSWORD_HYGIENE", label: "Password hygiene" },
  { value: "DATA_HANDLING", label: "Handling sensitive data" },
  { value: "APP_INFRA_MISTAKES", label: "Common app & infra mistakes" },
  { value: "CUSTOM", label: "Custom topic" },
];

const STATUS_LABEL: Record<TrainingStatus, string> = {
  SCHEDULED: "Scheduled",
  COMPLETED: "Completed",
  CANCELLED: "Cancelled",
};

export function TrainingTab({ engagementId }: { engagementId: string }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [sessions, setSessions] = useState<TrainingSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  function reload() {
    setLoading(true);
    api
      .get<TrainingSession[]>(`/engagements/${engagementId}/training-sessions`)
      .then(setSessions)
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  async function updateStatus(id: string, status: TrainingStatus) {
    await api.patch(`/training-sessions/${id}`, { status });
    reload();
  }

  return (
    <div className="flex flex-col gap-5">
      {isAdmin && (
        <div className="flex justify-end">
          <Button variant="outline" onClick={() => setShowForm((s) => !s)}>
            {showForm ? "Cancel" : "+ Schedule session"}
          </Button>
        </div>
      )}

      {showForm && (
        <Card>
          <NewSessionForm
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
      ) : sessions.length === 0 ? (
        <EmptyState title="No training sessions yet" hint="Schedule a phishing, password-hygiene, or data-handling session for this client's staff." />
      ) : (
        <Card className="overflow-hidden !p-0">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-line-soft text-xs uppercase tracking-wide text-ink-faint">
                <th className="px-5 py-3 font-medium">Topic</th>
                <th className="px-5 py-3 font-medium">Scheduled</th>
                <th className="px-5 py-3 font-medium">Attendees</th>
                <th className="px-5 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id} className="border-b border-line-soft last:border-0">
                  <td className="px-5 py-3 font-medium text-ink">
                    {s.topic === "CUSTOM" ? s.customTopic : TOPICS.find((t) => t.value === s.topic)?.label}
                  </td>
                  <td className="px-5 py-3 text-ink-soft">{new Date(s.scheduledAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}</td>
                  <td className="px-5 py-3 text-ink-soft">{s.attendeeCount ?? "—"}</td>
                  <td className="px-5 py-3">
                    {isAdmin ? (
                      <select
                        value={s.status}
                        onChange={(e) => updateStatus(s.id, e.target.value as TrainingStatus)}
                        className={`${inputClass} !py-1.5 text-xs`}
                      >
                        {Object.entries(STATUS_LABEL).map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span className="text-ink-soft">{STATUS_LABEL[s.status]}</span>
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

function NewSessionForm({ engagementId, onCreated }: { engagementId: string; onCreated: () => void }) {
  const [topic, setTopic] = useState<TrainingTopic>("PHISHING");
  const [customTopic, setCustomTopic] = useState("");
  const [scheduledAt, setScheduledAt] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.post(`/engagements/${engagementId}/training-sessions`, {
        topic,
        customTopic: topic === "CUSTOM" ? customTopic : undefined,
        scheduledAt,
        notes: notes || undefined,
      });
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't schedule the session.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      <Field label="Topic">
        <select value={topic} onChange={(e) => setTopic(e.target.value as TrainingTopic)} className={inputClass}>
          {TOPICS.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Date">
        <input
          type="date"
          required
          value={scheduledAt}
          onChange={(e) => setScheduledAt(e.target.value)}
          className={inputClass}
        />
      </Field>
      {topic === "CUSTOM" && (
        <div className="sm:col-span-2">
          <Field label="Custom topic name">
            <input required value={customTopic} onChange={(e) => setCustomTopic(e.target.value)} className={inputClass} />
          </Field>
        </div>
      )}
      <div className="sm:col-span-2">
        <Field label="Notes / materials link (encrypted at rest)">
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} className={`${inputClass} min-h-16`} />
        </Field>
      </div>
      {error && <p className="sm:col-span-2 text-sm text-[color:var(--color-risk-critical)]">{error}</p>}
      <div className="sm:col-span-2">
        <Button type="submit" disabled={submitting}>
          {submitting ? "Scheduling…" : "Schedule session"}
        </Button>
      </div>
    </form>
  );
}

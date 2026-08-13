import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import type { Client, ComplianceSummary, Engagement, Finding, Severity, Test } from "../../lib/types";
import { TopBar } from "../../components/TopBar";
import { Card, DarkCard, Button, EmptyState } from "../../components/ui";
import { ProgressRing } from "../../components/ProgressRing";
import { SeverityDot, StatusPill } from "../../components/Severity";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

interface EngagementRollup {
  engagement: Engagement;
  findings: Finding[];
  tests: Test[];
  compliance: ComplianceSummary | null;
}

export default function Dashboard() {
  const { user } = useAuth();
  const isAdmin = user?.role === "SECURITY_ADMIN";
  const [clients, setClients] = useState<Client[]>([]);
  const [rollups, setRollups] = useState<EngagementRollup[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      const [clientList, engagementList] = await Promise.all([
        api.get<Client[]>("/clients"),
        api.get<Engagement[]>("/engagements"),
      ]);
      if (cancelled) return;
      setClients(clientList);

      const withDetail = await Promise.all(
        engagementList.map(async (engagement): Promise<EngagementRollup> => {
          const [findings, tests, compliance] = await Promise.all([
            api.get<Finding[]>(`/engagements/${engagement.id}/findings`),
            api.get<Test[]>(`/engagements/${engagement.id}/tests`).catch(() => []),
            api
              .get<ComplianceSummary>(`/engagements/${engagement.id}/compliance-summary`)
              .catch(() => null),
          ]);
          return { engagement, findings, tests, compliance };
        })
      );
      if (!cancelled) {
        setRollups(withDetail);
        setLoading(false);
      }
    }

    load().catch(() => setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const r of rollups) for (const f of r.findings) counts[f.severity]++;
    return counts;
  }, [rollups]);

  const maxSeverityCount = Math.max(1, ...Object.values(severityCounts));

  const activeEngagements = rollups.filter((r) => r.engagement.status !== "CLOSED").length;

  const complianceRate = useMemo(() => {
    let pass = 0;
    let total = 0;
    for (const r of rollups) {
      if (!r.compliance) continue;
      for (const counts of Object.values(r.compliance.byFramework)) {
        pass += counts.PASS ?? 0;
        total += Object.values(counts).reduce((a, b) => a + b, 0);
      }
    }
    return total === 0 ? null : Math.round((pass / total) * 100);
  }, [rollups]);

  const openCriticalFindings = useMemo(
    () =>
      rollups
        .flatMap((r) => r.findings.map((f) => ({ ...f, engagementId: r.engagement.id, clientName: r.engagement.client?.name })))
        .filter((f) => (f.severity === "CRITICAL" || f.severity === "HIGH") && f.status === "OPEN")
        .slice(0, 5),
    [rollups]
  );

  const testsInProgress = useMemo(
    () =>
      rollups
        .flatMap((r) => r.tests.map((t) => ({ ...t, clientName: r.engagement.client?.name })))
        .filter((t) => t.status === "IN_PROGRESS")
        .slice(0, 3),
    [rollups]
  );

  const recentEngagements = rollups.slice(0, 3);
  const recentClients = clients.slice(0, 5);

  if (loading) {
    return (
      <>
        <TopBar title={`Hi, ${user?.name?.split(" ")[0] ?? "there"}`} subtitle="Loading your workspace…" />
        <div className="grid grid-cols-3 gap-5">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-40 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
          ))}
        </div>
      </>
    );
  }

  if (clients.length === 0) {
    return (
      <>
        <TopBar title={`Hi, ${user?.name?.split(" ")[0] ?? "there"}`} subtitle="Nothing on the books yet." />
        <EmptyState
          title={isAdmin ? "No clients yet" : "No engagements yet"}
          hint={isAdmin ? "Add your first client to start scoping an engagement." : "Your security team hasn't linked an engagement to your account yet."}
          action={
            isAdmin ? (
              <Link to="/clients">
                <Button>+ Add a client</Button>
              </Link>
            ) : undefined
          }
        />
      </>
    );
  }

  return (
    <>
      <TopBar
        title={`Hi, ${user?.name?.split(" ")[0] ?? "there"}`}
        subtitle={isAdmin ? "Here's what's moving across your engagements." : "Here's where your assessment stands."}
        actions={
          isAdmin && (
            <Link to="/clients">
              <Button>+ New engagement</Button>
            </Link>
          )
        }
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <DarkCard>
          <p className="text-sm font-medium text-paper/60">Overview</p>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <div className="rounded-2xl bg-paper/10 p-4">
              <p className="text-2xl font-extrabold">{clients.length}</p>
              <p className="mt-1 text-xs text-paper/60">{isAdmin ? "Clients" : "Your organization"}</p>
            </div>
            <div className="rounded-2xl bg-paper/10 p-4">
              <p className="text-2xl font-extrabold">{activeEngagements}</p>
              <p className="mt-1 text-xs text-paper/60">Active engagements</p>
            </div>
          </div>
        </DarkCard>

        <Card>
          <p className="text-sm font-medium text-ink-soft">Findings by severity</p>
          <div className="mt-5 flex flex-col gap-2.5">
            {SEVERITIES.map((sev) => (
              <div key={sev} className="flex items-center gap-3">
                <span className="flex w-16 items-center gap-1.5 text-xs font-medium text-ink-soft">
                  <SeverityDot severity={sev} />
                  {sev.slice(0, 4)}
                </span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-line-soft">
                  <div
                    className="h-full rounded-full bg-ink/70 transition-all duration-500"
                    style={{ width: `${(severityCounts[sev] / maxSeverityCount) * 100}%` }}
                  />
                </div>
                <span className="w-5 text-right text-xs font-semibold text-ink">{severityCounts[sev]}</span>
              </div>
            ))}
          </div>
        </Card>

        <DarkCard className="flex flex-col items-center justify-center text-center">
          <p className="self-start text-sm font-medium text-paper/60">Compliance readiness</p>
          <ProgressRing
            value={complianceRate ?? 0}
            trackClassName="stroke-paper/15"
            progressClassName="stroke-paper"
            label={complianceRate === null ? "—" : `${complianceRate}%`}
            sublabel="pass rate"
          />
          <p className="mt-3 text-xs text-paper/60">
            {complianceRate === null ? "No compliance checks logged yet" : "Across all logged controls"}
          </p>
        </DarkCard>
      </div>

      <div className={`grid grid-cols-1 gap-5 ${isAdmin && recentClients.length > 0 ? "lg:grid-cols-3" : "lg:grid-cols-2"}`}>
        {isAdmin && recentClients.length > 0 && (
          <Card>
            <p className="mb-4 text-sm font-medium text-ink-soft">Recent clients</p>
            <div className="flex flex-col gap-0.5">
              {recentClients.map((client) => (
                <Link
                  key={client.id}
                  to={`/clients/${client.id}`}
                  className="flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-sm text-ink-soft transition-colors hover:bg-line-soft hover:text-ink"
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ink/30" />
                  <span className="truncate">{client.name}</span>
                </Link>
              ))}
            </div>
          </Card>
        )}
        <Card>
          <p className="mb-4 text-sm font-medium text-ink-soft">Open critical &amp; high findings</p>
          {openCriticalFindings.length === 0 ? (
            <p className="py-6 text-center text-sm text-ink-faint">Nothing open at this severity. Good sign.</p>
          ) : (
            <div className="flex flex-col gap-1">
              {openCriticalFindings.map((f) => (
                <Link
                  key={f.id}
                  to={`/engagements/${f.engagementId}`}
                  className="flex items-center justify-between gap-3 rounded-2xl px-3 py-2.5 transition-colors hover:bg-line-soft"
                >
                  <span className="flex items-center gap-2.5 truncate">
                    <SeverityDot severity={f.severity} />
                    <span className="truncate text-sm text-ink">{f.title}</span>
                  </span>
                  <span className="shrink-0 text-xs text-ink-faint">{f.clientName}</span>
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <p className="mb-4 text-sm font-medium text-ink-soft">Tests in progress</p>
          {testsInProgress.length === 0 ? (
            <p className="py-6 text-center text-sm text-ink-faint">No active testing right now.</p>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {testsInProgress.map((t) => (
                <div key={t.id} className="rounded-2xl border border-line-soft bg-paper p-4">
                  <p className="text-xs font-semibold uppercase tracking-wide text-ink-faint">{t.type.replace("_", " ")}</p>
                  <p className="mt-1 truncate text-sm font-medium text-ink">{t.clientName}</p>
                  <div className="mt-3">
                    <StatusPill status={t.status} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card>
        <div className="mb-4 flex items-center justify-between">
          <p className="text-sm font-medium text-ink-soft">Recent engagements</p>
          <Link to="/clients" className="text-xs font-semibold text-ink-soft hover:text-ink">
            View all clients →
          </Link>
        </div>
        {recentEngagements.length === 0 ? (
          <p className="py-6 text-center text-sm text-ink-faint">No engagements yet.</p>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {recentEngagements.map(({ engagement }) => (
              <Link
                key={engagement.id}
                to={`/engagements/${engagement.id}`}
                className="rounded-2xl bg-ink p-4 text-paper transition-transform hover:-translate-y-0.5"
              >
                <p className="truncate text-sm font-semibold">{engagement.client?.name ?? "Engagement"}</p>
                <p className="mt-1 text-xs text-paper/60">
                  {new Date(engagement.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
                </p>
                <div className="mt-3">
                  <span className="inline-flex items-center rounded-full bg-paper/15 px-2.5 py-1 text-xs font-semibold text-paper">
                    {engagement.status === "SCOPING" ? "Scoping" : engagement.status.charAt(0) + engagement.status.slice(1).toLowerCase()}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}

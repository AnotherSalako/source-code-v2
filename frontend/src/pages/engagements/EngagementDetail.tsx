import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../../lib/api";
import { useAuth } from "../../lib/auth";
import type { Engagement } from "../../lib/types";
import { TopBar, AuthorizationPill } from "../../components/TopBar";
import { EmptyState } from "../../components/ui";
import { OverviewTab } from "./tabs/OverviewTab";
import { AssetsTab } from "./tabs/AssetsTab";
import { TestsTab } from "./tabs/TestsTab";
import { FindingsTab } from "./tabs/FindingsTab";
import { RoadmapTab } from "./tabs/RoadmapTab";
import { ComplianceTab } from "./tabs/ComplianceTab";
import { TrainingTab } from "./tabs/TrainingTab";
import { ReportsTab } from "./tabs/ReportsTab";

const TABS = ["Overview", "Assets", "Tests", "Findings", "Roadmap", "Compliance", "Training", "Reports"] as const;
type Tab = (typeof TABS)[number];

export default function EngagementDetail() {
  const { engagementId } = useParams<{ engagementId: string }>();
  const { user } = useAuth();
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>("Overview");

  function reload() {
    if (!engagementId) return;
    setLoading(true);
    api
      .get<Engagement>(`/engagements/${engagementId}`)
      .then(setEngagement)
      .finally(() => setLoading(false));
  }

  useEffect(reload, [engagementId]);

  if (loading) return <div className="h-64 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />;
  if (!engagement || !engagementId) {
    return <EmptyState title="Engagement not found" hint="It may have been removed, or you don't have access to it." />;
  }

  const authorized = Boolean(engagement.authorizationSignedAt);
  const visibleTabs = user?.role === "EXEC_CLIENT" ? (["Overview", "Roadmap", "Compliance", "Training", "Reports"] as const) : TABS;

  return (
    <>
      <TopBar
        title={engagement.client?.name ?? "Engagement"}
        subtitle={`Opened ${new Date(engagement.createdAt).toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" })}`}
        actions={<AuthorizationPill authorized={authorized} />}
      />

      <div className="flex gap-1 overflow-x-auto rounded-[var(--radius-pill)] border border-line-soft bg-surface/70 p-1 backdrop-blur-xl">
        {visibleTabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`shrink-0 rounded-full px-4 py-2 text-sm font-semibold transition-colors ${
              tab === t ? "bg-ink text-paper" : "text-ink-soft hover:text-ink"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Overview" && <OverviewTab engagement={engagement} onUpdated={reload} />}
      {tab === "Assets" && <AssetsTab engagementId={engagementId} authorized={authorized} />}
      {tab === "Tests" && <TestsTab engagementId={engagementId} authorized={authorized} />}
      {tab === "Findings" && <FindingsTab engagementId={engagementId} authorized={authorized} />}
      {tab === "Roadmap" && <RoadmapTab engagementId={engagementId} />}
      {tab === "Compliance" && <ComplianceTab engagementId={engagementId} />}
      {tab === "Training" && <TrainingTab engagementId={engagementId} />}
      {tab === "Reports" && <ReportsTab engagementId={engagementId} />}
    </>
  );
}

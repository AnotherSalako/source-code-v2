import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import type { SecurityStatus } from "../../lib/types";
import { TopBar } from "../../components/TopBar";
import { Card, DarkCard, SectionLabel } from "../../components/ui";
import { ProgressRing } from "../../components/ProgressRing";

interface Layer {
  key: string;
  label: string;
  met: boolean;
}

export default function SecurityOverview() {
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<SecurityStatus>("/security/status")
      .then(setStatus)
      .finally(() => setLoading(false));
  }, []);

  if (loading || !status) {
    return (
      <>
        <TopBar title="Security" subtitle="Every control actually protecting this deployment, live." />
        <div className="h-40 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-48 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
          ))}
        </div>
      </>
    );
  }

  // Six hardening controls, one per layer below — deliberately honest: a
  // dev/demo environment scoring 4/6 here isn't a bug in the page, it's
  // the page doing its job. Real KMS custody and non-intrusive scanning
  // are facts about the code, not togglable "controls," so they're shown
  // in their cards but don't factor into the score.
  const layers: Layer[] = [
    { key: "access", label: "Access", met: status.access.signupRestricted },
    { key: "encryption", label: "Key custody", met: status.encryption.kmsProvider === "aws" },
    { key: "rotation", label: "Key rotation", met: status.encryption.rotationScheduled },
    { key: "scanning", label: "Scan guardrails", met: !status.scanningSafety.allowInternalTargets },
    { key: "detection", label: "Detection", met: status.detectionResponse.malwareDetectionConfigured },
    { key: "authorization", label: "Authorization", met: status.detectionResponse.esignatureProvider !== "noop" },
  ];
  const metCount = layers.filter((l) => l.met).length;
  const score = Math.round((metCount / layers.length) * 100);

  return (
    <>
      <TopBar title="Security" subtitle="Every control actually protecting this deployment, live — not a claim, a live read of the running system." />

      <DarkCard className="flex flex-col gap-6 sm:flex-row sm:items-center sm:gap-10">
        <div className="flex shrink-0 flex-col items-center gap-2 sm:items-start">
          <ProgressRing value={score} label={`${metCount}/${layers.length}`} sublabel="hardened" />
        </div>
        <div className="flex-1">
          <p className="text-sm font-medium text-paper/60">Defense in depth</p>
          <p className="mt-1 text-xs text-paper/50">
            Each layer below only lights up when the underlying control is actually configured — this reads the
            running system, it doesn't assume anything.
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {layers.map((layer, i) => (
              <div key={layer.key} className="flex items-center gap-2">
                <span
                  className={`flex items-center gap-2 rounded-full px-3.5 py-2 text-xs font-semibold transition-colors ${
                    layer.met ? "bg-paper text-ink" : "bg-paper/10 text-paper/50"
                  }`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${layer.met ? "bg-secure" : "bg-paper/30"}`} />
                  {layer.label}
                </span>
                {i < layers.length - 1 && <span className="hidden h-px w-3 bg-paper/15 sm:block" />}
              </div>
            ))}
          </div>
        </div>
      </DarkCard>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2 xl:grid-cols-3">
        <Card className="flex flex-col gap-4">
          <SectionLabel>Access control</SectionLabel>
          <ControlRow
            label="Sign-up"
            met={status.access.signupRestricted}
            onText="Invite-only"
            offText="Public — anyone can register"
          />
          <div className="rounded-2xl bg-paper p-4">
            <p className="text-xs font-medium text-ink-faint">Team</p>
            <p className="mt-1 text-2xl font-extrabold text-ink">{status.access.teamSize}</p>
            <div className="mt-2 flex flex-wrap gap-1.5 text-[11px] text-ink-faint">
              <span>{status.access.roleBreakdown.SECURITY_ADMIN} admin</span>
              <span>·</span>
              <span>{status.access.roleBreakdown.TECHNICAL_CLIENT} technical</span>
              <span>·</span>
              <span>{status.access.roleBreakdown.EXEC_CLIENT} executive</span>
            </div>
          </div>
          <Link to="/team" className="text-xs font-semibold text-ink-soft hover:text-ink">
            Manage team →
          </Link>
        </Card>

        <Card className="flex flex-col gap-4">
          <SectionLabel>Encryption</SectionLabel>
          <ControlRow label="Algorithm" met sublabel="AES-256-GCM" staticFact />
          <ControlRow
            label="Key custody"
            met={status.encryption.kmsProvider === "aws"}
            onText="AWS KMS"
            offText="Local dev key — not production-grade"
          />
          <ControlRow
            label="Rotation"
            met={status.encryption.rotationScheduled}
            onText={`Scheduled · v${status.encryption.cmkVersion}`}
            offText="Not scheduled"
          />
        </Card>

        <Card className="flex flex-col gap-4">
          <SectionLabel>Scanning safety</SectionLabel>
          <ControlRow label="Template set" met sublabel="Non-intrusive only, fixed in code" staticFact />
          <ControlRow
            label="Target guardrail"
            met={!status.scanningSafety.allowInternalTargets}
            onText="Private networks blocked"
            offText="Internal targets allowed (dev only)"
          />
          <ControlRow
            label="Scheduled scans"
            met={status.scanningSafety.scheduledScanningConfigured}
            onText="Configured"
            offText="Not configured"
          />
        </Card>

        <Card className="flex flex-col gap-4">
          <SectionLabel>Detection &amp; alerting</SectionLabel>
          <ControlRow
            label="Malware detection"
            met={status.detectionResponse.malwareDetectionConfigured}
            onText="VirusTotal connected"
            offText="Not connected"
          />
          <ControlRow
            label="Slack alerts"
            met={status.detectionResponse.slackConfigured}
            onText="Connected"
            offText="Not connected"
          />
          <ControlRow
            label="Email alerts"
            met={status.detectionResponse.emailConfigured}
            onText="Connected"
            offText="Not connected"
          />
        </Card>

        <Card className="flex flex-col gap-4">
          <SectionLabel>Active response</SectionLabel>
          <ControlRow
            label="Containment"
            met={status.detectionResponse.activeResponseProvider !== "noop"}
            onText={status.detectionResponse.activeResponseProvider === "crowdstrike" ? "CrowdStrike connected" : "Not connected"}
            offText="Not connected"
          />
          <p className="text-xs text-ink-faint">
            Always triggered by a person clicking a button on a finding — never automatic, and limited to network
            containment, not file deletion or process termination.
          </p>
        </Card>

        <Card className="flex flex-col gap-4">
          <SectionLabel>Audit trail</SectionLabel>
          <div className="rounded-2xl bg-paper p-4">
            <p className="text-xs font-medium text-ink-faint">Events logged</p>
            <p className="mt-1 text-2xl font-extrabold text-ink">{status.audit.totalEvents.toLocaleString()}</p>
          </div>
          <ControlRow
            label="Denied attempts, 30d"
            met={status.audit.deniedLast30Days === 0}
            onText={String(status.audit.deniedLast30Days)}
            offText={String(status.audit.deniedLast30Days)}
            neutral
          />
          <Link to="/audit-log" className="text-xs font-semibold text-ink-soft hover:text-ink">
            View full log →
          </Link>
        </Card>
      </div>
    </>
  );
}

function ControlRow({
  label,
  met,
  onText,
  offText,
  sublabel,
  staticFact,
  neutral,
}: {
  label: string;
  met: boolean;
  onText?: string;
  offText?: string;
  sublabel?: string;
  staticFact?: boolean;
  neutral?: boolean;
}): ReactNode {
  const text = met ? onText : offText;
  const colorClass = neutral
    ? "bg-line-soft text-ink-soft"
    : staticFact
      ? "bg-line-soft text-ink-soft"
      : met
        ? "bg-secure/10 text-secure"
        : "bg-[color:var(--color-risk-medium)]/10 text-[color:var(--color-risk-medium)]";

  return (
    <div className="flex items-center justify-between gap-3">
      <div>
        <p className="text-sm text-ink">{label}</p>
        {sublabel && <p className="text-xs text-ink-faint">{sublabel}</p>}
      </div>
      <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${colorClass}`}>
        {!staticFact && !neutral && <span className={`h-1.5 w-1.5 rounded-full ${met ? "bg-secure" : "bg-[color:var(--color-risk-medium)]"}`} />}
        {text ?? (met ? "On" : "Off")}
      </span>
    </div>
  );
}

// Slack incoming webhooks are about as stable/simple as third-party APIs
// get — a POST of `{ text }` (or `{ blocks }`) to a workspace-specific URL,
// unauthenticated beyond the URL itself being secret. Confident in this
// shape (unlike Documenso's beta API); still untested against a real
// webhook — no credentials available in this environment. Create one at
// https://api.slack.com/messaging/webhooks (Slack app -> Incoming Webhooks).

import { NotificationProvider, FindingNotification, SweepHeartbeat, WeeklyDigest } from "../provider";

const SEVERITY_EMOJI: Record<string, string> = { CRITICAL: "🔴", HIGH: "🟠" };

// Slack's mrkdwn supports link syntax like `<https://evil.com|Click here>` —
// per Slack's own escaping requirements (api.slack.com/reference/surfaces/
// formatting#escaping), &/</> must be escaped before interpolating
// user-supplied text (clientName, title) into a message, or a crafted
// finding title could render as a clickable phishing link in the alert.
export function escapeMrkdwn(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export class SlackNotificationProvider implements NotificationProvider {
  constructor(private readonly webhookUrl: string) {}

  async notify(n: FindingNotification): Promise<void> {
    const clientName = escapeMrkdwn(n.clientName);
    const title = escapeMrkdwn(n.title);
    const res = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text:
          `${SEVERITY_EMOJI[n.severity] ?? ""} *${n.severity}* finding on *${clientName}*\n` +
          `${title}\n` +
          `Engagement: ${n.engagementId}`,
      }),
    });
    if (!res.ok) throw new Error(`Slack webhook failed: HTTP ${res.status}`);
  }

  async notifyHeartbeat(h: SweepHeartbeat): Promise<void> {
    const res = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text:
          `🟢 Scheduled scan sweep ran at ${h.timestamp.toISOString()}\n` +
          `${h.eligibleCount} asset(s) eligible · ${h.startedCount} scan(s) started · ${h.skippedCount} skipped`,
      }),
    });
    if (!res.ok) throw new Error(`Slack webhook failed: HTTP ${res.status}`);
  }

  async notifyDigest(d: WeeklyDigest): Promise<void> {
    const severityLine = d.newFindingsBySeverity.length
      ? d.newFindingsBySeverity.map((s) => `${s.severity} ${s.count}`).join(" · ")
      : "none";
    const staleLine = d.staleAgents.length
      ? d.staleAgents.map((a) => `${escapeMrkdwn(a.deviceName)} (${escapeMrkdwn(a.clientName)})`).join(", ")
      : "none";
    const res = await fetch(this.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text:
          `📋 *Weekly Jupiter digest* — since ${d.since.toISOString().slice(0, 10)}\n` +
          `*New findings:* ${d.totalNewFindings} (${severityLine})\n` +
          `*Drift alerts (new watch-mode changes):* ${d.driftAlerts}\n` +
          `*Active engagements:* ${d.activeEngagements}\n` +
          `*Agents silent 7+ days:* ${staleLine}`,
      }),
    });
    if (!res.ok) throw new Error(`Slack webhook failed: HTTP ${res.status}`);
  }
}

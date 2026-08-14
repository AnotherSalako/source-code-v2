// Resend (https://resend.com) — a modern transactional email API, chosen
// over SES/SendGrid for how little setup it needs to get a first email out
// (a domain-verified `from` address and one API key). Untested against a
// live account — no credentials available — but this is ordinary REST
// usage against one well-documented endpoint.

import { NotificationProvider, FindingNotification, SweepHeartbeat, WeeklyDigest } from "../provider";

const SEVERITY_COLOR: Record<string, string> = { CRITICAL: "#b91c1c", HIGH: "#c2410c" };

// clientName/title are user-supplied (client name at intake, finding title
// by whoever logged it) and land in this HTML email body verbatim — escape
// before interpolating so a title like `<img src=x onerror=...>` can't run
// in whatever mail client renders it.
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export class ResendNotificationProvider implements NotificationProvider {
  constructor(
    private readonly apiKey: string,
    private readonly from: string,
    private readonly to: string
  ) {}

  async notify(n: FindingNotification): Promise<void> {
    const clientName = escapeHtml(n.clientName);
    const title = escapeHtml(n.title);
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: this.from,
        to: this.to,
        subject: `[${n.severity}] New finding — ${n.clientName}`,
        html:
          `<p><strong style="color:${SEVERITY_COLOR[n.severity] ?? "#111"}">${n.severity}</strong> finding logged for <strong>${clientName}</strong>.</p>` +
          `<p>${title}</p>` +
          `<p style="color:#666;font-size:12px">Engagement: ${n.engagementId}</p>`,
      }),
    });
    if (!res.ok) throw new Error(`Resend send failed: HTTP ${res.status}`);
  }

  async notifyHeartbeat(h: SweepHeartbeat): Promise<void> {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: this.from,
        to: this.to,
        subject: `Jupiter scan sweep — ${h.startedCount} started, ${h.skippedCount} skipped`,
        html:
          `<p style="color:#666;font-size:13px">Scheduled scan sweep ran at ${h.timestamp.toISOString()}.</p>` +
          `<p>${h.eligibleCount} asset(s) eligible · ${h.startedCount} scan(s) started · ${h.skippedCount} skipped.</p>`,
      }),
    });
    if (!res.ok) throw new Error(`Resend send failed: HTTP ${res.status}`);
  }

  async notifyDigest(d: WeeklyDigest): Promise<void> {
    const severityRows = d.newFindingsBySeverity.length
      ? d.newFindingsBySeverity.map((s) => `<li>${escapeHtml(s.severity)}: ${s.count}</li>`).join("")
      : "<li>none</li>";
    const staleRows = d.staleAgents.length
      ? d.staleAgents
          .map(
            (a) =>
              `<li>${escapeHtml(a.deviceName)} (${escapeHtml(a.clientName)}) — last seen ${a.lastCheckInAt ? a.lastCheckInAt.toISOString() : "never"}</li>`
          )
          .join("")
      : "<li>none</li>";
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: this.from,
        to: this.to,
        subject: `Jupiter weekly digest — ${d.totalNewFindings} new finding(s), ${d.driftAlerts} drift alert(s)`,
        html:
          `<p style="color:#666;font-size:13px">Since ${d.since.toISOString().slice(0, 10)}.</p>` +
          `<p><strong>New findings:</strong> ${d.totalNewFindings}</p><ul>${severityRows}</ul>` +
          `<p><strong>Drift alerts (new watch-mode changes):</strong> ${d.driftAlerts}</p>` +
          `<p><strong>Active engagements:</strong> ${d.activeEngagements}</p>` +
          `<p><strong>Agents silent 7+ days:</strong></p><ul>${staleRows}</ul>`,
      }),
    });
    if (!res.ok) throw new Error(`Resend send failed: HTTP ${res.status}`);
  }
}

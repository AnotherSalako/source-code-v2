export interface FindingNotification {
  findingId: string;
  title: string;
  severity: "CRITICAL" | "HIGH";
  engagementId: string;
  clientName: string;
}

/**
 * A periodic "the automated sweep actually ran" signal, distinct from
 * FindingNotification — sent on every scheduled-scan sweep regardless of
 * whether anything severe (or anything at all) was found. Without this,
 * silence from the alert channel is ambiguous: it could mean "all clear" or
 * "the cron died three days ago and nobody noticed." A heartbeat makes
 * silence from *this* mean only one thing — broken.
 */
export interface SweepHeartbeat {
  eligibleCount: number;
  startedCount: number;
  skippedCount: number;
  timestamp: Date;
}

/**
 * Weekly ops summary (src/modules/internal/digest.service.ts) — platform-wide,
 * not per-client: this goes to whoever runs Jupiter (the same
 * NOTIFICATION_EMAIL_TO/SLACK_WEBHOOK_URL every other notification here
 * targets), not to client contacts. Turns the platform from "something you
 * have to log into" into something that proactively surfaces what changed.
 */
export interface WeeklyDigest {
  since: Date;
  totalNewFindings: number;
  newFindingsBySeverity: { severity: string; count: number }[];
  driftAlerts: number;
  activeEngagements: number;
  staleAgents: { deviceName: string; clientName: string; lastCheckInAt: Date | null }[];
}

/**
 * Fan-out, not swappable-single like KmsProvider/ThreatResponseProvider —
 * you might reasonably want both Slack and email at once, so
 * src/notifications/index.ts builds a NotificationProvider[] from whichever
 * are configured (possibly zero, possibly both) rather than picking one.
 */
export interface NotificationProvider {
  notify(n: FindingNotification): Promise<void>;
  notifyHeartbeat(h: SweepHeartbeat): Promise<void>;
  notifyDigest(d: WeeklyDigest): Promise<void>;
}

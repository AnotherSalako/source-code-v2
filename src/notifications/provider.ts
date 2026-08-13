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
 * Fan-out, not swappable-single like KmsProvider/ThreatResponseProvider —
 * you might reasonably want both Slack and email at once, so
 * src/notifications/index.ts builds a NotificationProvider[] from whichever
 * are configured (possibly zero, possibly both) rather than picking one.
 */
export interface NotificationProvider {
  notify(n: FindingNotification): Promise<void>;
  notifyHeartbeat(h: SweepHeartbeat): Promise<void>;
}

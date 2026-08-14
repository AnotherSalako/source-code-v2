import { env } from "../config/env";
import { logger } from "../config/logger";
import { prisma } from "../db/prisma";
import { NotificationProvider, FindingNotification, SweepHeartbeat, WeeklyDigest } from "./provider";
import { SlackNotificationProvider } from "./providers/slack";
import { ResendNotificationProvider } from "./providers/resend";

function buildNotifiers(): NotificationProvider[] {
  const notifiers: NotificationProvider[] = [];
  if (env.slackWebhookUrl) notifiers.push(new SlackNotificationProvider(env.slackWebhookUrl));
  if (env.resendApiKey && env.notificationEmailFrom && env.notificationEmailTo) {
    notifiers.push(new ResendNotificationProvider(env.resendApiKey, env.notificationEmailFrom, env.notificationEmailTo));
  }
  return notifiers;
}

const notifiers = buildNotifiers();

/**
 * Fire-and-forget, called from every finding-creation path (manual create,
 * bulk import, automated/scheduled scans — all three funnel through
 * src/modules/findings/import.service.ts or findings.routes.ts). No-ops
 * cleanly with zero configured notifiers rather than needing a check at
 * every call site. One failing notifier doesn't block another
 * (Promise.allSettled) — a broken Slack webhook shouldn't also silently
 * kill email delivery.
 */
export async function notifyIfSevere(params: { findingId: string; title: string; severity: string; engagementId: string }): Promise<void> {
  if (notifiers.length === 0) return;
  if (params.severity !== "CRITICAL" && params.severity !== "HIGH") return;

  const engagement = await prisma.engagement.findUnique({
    where: { id: params.engagementId },
    select: { client: { select: { name: true } } },
  });

  const notification: FindingNotification = {
    findingId: params.findingId,
    title: params.title,
    severity: params.severity,
    engagementId: params.engagementId,
    clientName: engagement?.client.name ?? "Unknown client",
  };

  const results = await Promise.allSettled(notifiers.map((n) => n.notify(notification)));
  for (const result of results) {
    if (result.status === "rejected") logger.error({ err: result.reason, findingId: params.findingId }, "Finding notification failed");
  }
}

/**
 * Fired at the end of every scheduled-scan sweep, regardless of outcome —
 * unlike notifyIfSevere, this isn't conditional on anything being found.
 * The point isn't the content, it's the cadence: if this stops arriving,
 * that's the signal something's broken, since a "0 eligible, 0 started"
 * heartbeat is itself a normal, expected message, not silence.
 */
export async function notifySweepHeartbeat(h: SweepHeartbeat): Promise<void> {
  if (notifiers.length === 0) return;

  const results = await Promise.allSettled(notifiers.map((n) => n.notifyHeartbeat(h)));
  for (const result of results) {
    if (result.status === "rejected") logger.error({ err: result.reason }, "Sweep heartbeat notification failed");
  }
}

/**
 * Fired once a week by GET /internal/weekly-digest (see vercel.json "crons").
 * Same no-op-with-zero-notifiers shape as the other two — a digest with no
 * one to receive it is just wasted computation, not an error.
 */
export async function notifyWeeklyDigest(d: WeeklyDigest): Promise<void> {
  if (notifiers.length === 0) return;

  const results = await Promise.allSettled(notifiers.map((n) => n.notifyDigest(d)));
  for (const result of results) {
    if (result.status === "rejected") logger.error({ err: result.reason }, "Weekly digest notification failed");
  }
}

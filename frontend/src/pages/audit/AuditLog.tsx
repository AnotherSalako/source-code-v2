import { useEffect, useState } from "react";
import { api } from "../../lib/api";
import type { AuditLogEntry } from "../../lib/types";
import { TopBar } from "../../components/TopBar";
import { Card, EmptyState } from "../../components/ui";

const ACTION_LABEL: Record<string, string> = {
  VIEW: "Viewed",
  CREATE: "Created",
  UPDATE: "Updated",
  DELETE: "Deleted",
  DOWNLOAD: "Downloaded",
  DECRYPT: "Decrypted",
  LOGIN: "Signed in",
  LOGIN_FAILED: "Failed sign-in",
};

export default function AuditLog() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<AuditLogEntry[]>("/audit-logs?limit=200")
      .then(setLogs)
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <TopBar title="Audit log" subtitle="Every view, download, and decrypt of sensitive data, logged before the response is returned." />

      {loading ? (
        <div className="h-64 animate-pulse rounded-[var(--radius-card)] bg-line-soft" />
      ) : logs.length === 0 ? (
        <EmptyState title="No activity recorded yet" />
      ) : (
        <Card className="overflow-hidden !p-0">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-line-soft text-xs uppercase tracking-wide text-ink-faint">
                <th className="px-5 py-3 font-medium">Action</th>
                <th className="px-5 py-3 font-medium">Resource</th>
                <th className="px-5 py-3 font-medium">Result</th>
                <th className="px-5 py-3 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b border-line-soft last:border-0">
                  <td className="px-5 py-3 font-medium text-ink">{ACTION_LABEL[log.action] ?? log.action}</td>
                  <td className="px-5 py-3 font-mono text-xs text-ink-soft">
                    {log.resourceType}
                    {log.resourceId ? `:${log.resourceId.slice(0, 8)}` : ""}
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${
                        log.result === "SUCCESS" ? "bg-secure/10 text-secure" : "bg-[color:var(--color-risk-critical)]/10 text-[color:var(--color-risk-critical)]"
                      }`}
                    >
                      {log.result === "SUCCESS" ? "Allowed" : "Denied"}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-xs text-ink-faint">{new Date(log.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </>
  );
}

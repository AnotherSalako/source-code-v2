import { useState } from "react";

function LockIcon({ open }: { open: boolean }) {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
      <rect x="5" y="11" width="14" height="10" rx="2.5" stroke="currentColor" strokeWidth="1.8" />
      <path
        d={open ? "M8 11V8a4 4 0 0 1 7-2.6" : "M8 11V8a4 4 0 0 1 8 0v3"}
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        fill="none"
      />
    </svg>
  );
}

/**
 * Mirrors what the API actually does: GET /findings/:id decrypts server-side
 * and writes an audit log entry the moment it's called. Nothing is fetched
 * until this is opened, so "reveal" here is the real decrypt event, not a
 * cosmetic toggle over data that was already sitting in memory.
 */
export function EncryptedField({
  label,
  value,
  loading = false,
}: {
  label: string;
  value: string | undefined;
  loading?: boolean;
}) {
  const [revealedAt] = useState(() => (value !== undefined ? new Date() : null));

  return (
    <div>
      <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.1em] text-ink-faint">
        <LockIcon open={value !== undefined} />
        {label}
        {value !== undefined && revealedAt && (
          <span className="ml-1 inline-flex items-center gap-1 rounded-full bg-secure/10 px-2 py-0.5 font-mono text-[10px] font-medium normal-case tracking-normal text-secure">
            access logged · {revealedAt.toLocaleTimeString()}
          </span>
        )}
      </div>
      {loading ? (
        <div className="h-4 w-2/3 animate-pulse rounded bg-line-soft" />
      ) : (
        <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink">{value || "—"}</p>
      )}
    </div>
  );
}

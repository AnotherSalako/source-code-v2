import type { ReactNode } from "react";
import { UserButton } from "@clerk/clerk-react";
import { useAuth } from "../lib/auth";
import { IconButton, Pill } from "./ui";

const ROLE_LABEL: Record<string, string> = {
  SECURITY_ADMIN: "Security team",
  TECHNICAL_CLIENT: "Technical",
  EXEC_CLIENT: "Executive",
};

export function TopBar({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  const { user } = useAuth();

  return (
    <header className="flex items-center justify-between gap-4">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-faint">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {actions}
        <IconButton aria-label="Search" title="Search">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
            <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.8" />
            <path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
        </IconButton>
        <div className="flex items-center gap-2.5 rounded-full border border-line-soft bg-surface py-1 pl-1 pr-3 shadow-[var(--shadow-lift)]">
          {/* Clerk's own avatar + "Manage account" (includes MFA/security settings) + sign-out menu */}
          <UserButton appearance={{ elements: { avatarBox: "h-8 w-8" } }} />
          <div className="leading-tight">
            <p className="text-xs font-semibold text-ink">{user?.name}</p>
            <p className="text-[11px] text-ink-faint">{ROLE_LABEL[user?.role ?? ""] ?? user?.role}</p>
          </div>
        </div>
      </div>
    </header>
  );
}

export function AuthorizationPill({ authorized }: { authorized: boolean }) {
  return (
    <Pill className={authorized ? "bg-secure/10 text-secure" : "bg-[color:var(--color-risk-critical)]/10 text-[color:var(--color-risk-critical)]"}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {authorized ? "Authorized" : "Not authorized — testing blocked"}
    </Pill>
  );
}

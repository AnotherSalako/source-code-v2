import { useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { UserButton } from "@clerk/clerk-react";
import { useAuth } from "../lib/auth";
import { useTheme } from "../lib/theme";
import { api } from "../lib/api";
import type { Client } from "../lib/types";
import { Pill } from "./ui";

const ROLE_LABEL: Record<string, string> = {
  SECURITY_ADMIN: "Security team",
  TECHNICAL_CLIENT: "Technical",
  EXEC_CLIENT: "Executive",
};

/** Jumps straight to a client record by name — the one thing worth searching globally across every role. */
function ClientQuickSearch() {
  const navigate = useNavigate();
  const [clients, setClients] = useState<Client[]>([]);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api
      .get<Client[]>("/clients")
      .then(setClients)
      .catch(() => setClients([]));
  }, []);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  const matches = query.trim() ? clients.filter((c) => c.name.toLowerCase().includes(query.trim().toLowerCase())).slice(0, 6) : [];

  function goTo(client: Client) {
    navigate(`/clients/${client.id}`);
    setQuery("");
    setOpen(false);
  }

  return (
    <div ref={containerRef} className="relative hidden w-72 md:block">
      <svg
        width="15"
        height="15"
        viewBox="0 0 24 24"
        fill="none"
        className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-ink-faint"
      >
        <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.8" />
        <path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
      <input
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        placeholder="Search clients…"
        className="w-full rounded-full border border-line-soft bg-[color:var(--color-surface-glass)] py-2.5 pl-10 pr-4 text-sm text-ink shadow-[var(--shadow-lift)] backdrop-blur-xl backdrop-saturate-150 outline-none transition-colors placeholder:text-ink-faint focus:border-ink/30"
      />
      {open && matches.length > 0 && (
        <div className="absolute left-0 right-0 top-full z-30 mt-2 overflow-hidden rounded-2xl border border-line bg-[color:var(--color-surface-glass)] shadow-[var(--shadow-lift-lg)] backdrop-blur-2xl backdrop-saturate-150">
          {matches.map((c) => (
            <button
              key={c.id}
              onClick={() => goTo(c)}
              className="flex w-full items-center gap-2.5 px-4 py-2.5 text-left text-sm text-ink transition-colors hover:bg-line-soft"
            >
              <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ink/30" />
              <span className="truncate">{c.name}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <div className="flex items-center gap-0.5 rounded-full border border-line-soft bg-[color:var(--color-surface-glass)] p-1 shadow-[var(--shadow-lift)] backdrop-blur-xl backdrop-saturate-150">
      <button
        onClick={() => theme !== "light" && toggle()}
        aria-label="Light mode"
        aria-pressed={theme === "light"}
        className={`flex h-8 w-8 items-center justify-center rounded-full transition-colors ${
          theme === "light" ? "bg-ink text-paper" : "text-ink-faint hover:text-ink"
        }`}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="4.5" fill="currentColor" />
          <path
            d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
          />
        </svg>
      </button>
      <button
        onClick={() => theme !== "dark" && toggle()}
        aria-label="Dark mode"
        aria-pressed={theme === "dark"}
        className={`flex h-8 w-8 items-center justify-center rounded-full transition-colors ${
          theme === "dark" ? "bg-ink text-paper" : "text-ink-faint hover:text-ink"
        }`}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
          <path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5Z" fill="currentColor" />
        </svg>
      </button>
    </div>
  );
}

export function TopBar({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  const { user } = useAuth();

  return (
    <header className="flex flex-wrap items-center justify-between gap-4">
      <div>
        <h1 className="text-2xl font-extrabold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-faint">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        <ClientQuickSearch />
        {actions}
        <ThemeToggle />
        <div className="flex items-center gap-2.5 rounded-full border border-line-soft bg-[color:var(--color-surface-glass)] py-1 pl-1 pr-3 shadow-[var(--shadow-lift)] backdrop-blur-xl backdrop-saturate-150">
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

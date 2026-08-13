import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import type { Client } from "../lib/types";

function Logomark() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2 L21 6 V12 C21 17 17.5 20.5 12 22 C6.5 20.5 3 17 3 12 V6 Z"
        fill="currentColor"
      />
      <path d="M8.5 12 L11 14.5 L16 9" stroke="var(--color-paper)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const navIcon = {
  dashboard: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <rect x="3" y="3" width="8" height="8" rx="2.5" fill="currentColor" />
      <rect x="13" y="3" width="8" height="5" rx="2.5" fill="currentColor" opacity="0.4" />
      <rect x="13" y="10" width="8" height="11" rx="2.5" fill="currentColor" opacity="0.4" />
      <rect x="3" y="13" width="8" height="8" rx="2.5" fill="currentColor" opacity="0.4" />
    </svg>
  ),
  clients: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <circle cx="9" cy="8" r="3.4" fill="currentColor" />
      <path d="M3 20c0-3.6 2.7-6 6-6s6 2.4 6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
      <circle cx="18" cy="9" r="2.6" fill="currentColor" opacity="0.45" />
      <path d="M21.5 20c0-2.8-1.8-4.8-4-5.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.45" fill="none" />
    </svg>
  ),
  audit: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <rect x="4" y="3" width="16" height="18" rx="2.5" stroke="currentColor" strokeWidth="1.8" fill="none" />
      <path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  ),
  team: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <circle cx="8" cy="8" r="3" fill="currentColor" />
      <circle cx="16" cy="8" r="3" fill="currentColor" opacity="0.45" />
      <path d="M2.5 20c0-3.3 2.5-5.5 5.5-5.5s5.5 2.2 5.5 5.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
      <path d="M12.5 14.7c2.7.3 4.5 2.4 4.5 5.3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.45" fill="none" />
    </svg>
  ),
  security: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M12 2 L20 5.5 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V5.5 Z" fill="currentColor" opacity="0.15" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8.5 12 L11 14.5 L15.5 9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
};

const links = [
  { to: "/", label: "Dashboard", icon: navIcon.dashboard, end: true },
  { to: "/clients", label: "Clients", icon: navIcon.clients, end: false },
];

export function Sidebar() {
  const { user } = useAuth();
  const [recentClients, setRecentClients] = useState<Client[]>([]);

  useEffect(() => {
    api
      .get<Client[]>("/clients")
      .then((clients) => setRecentClients(clients.slice(0, 4)))
      .catch(() => setRecentClients([]));
  }, []);

  return (
    <aside className="flex h-full w-64 shrink-0 flex-col gap-6 rounded-[var(--radius-card)] border border-line bg-surface/90 p-5 shadow-[var(--shadow-lift)] backdrop-blur-xl">
      <div className="flex items-center gap-2 px-1">
        <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-ink text-paper">
          <Logomark />
        </span>
        <span className="text-base font-extrabold tracking-tight">Enforcer</span>
      </div>

      <nav className="flex flex-col gap-1">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.end}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-2xl px-3.5 py-2.5 text-sm font-medium transition-colors ${
                isActive ? "bg-ink text-paper" : "text-ink-soft hover:bg-line-soft hover:text-ink"
              }`
            }
          >
            {link.icon}
            {link.label}
          </NavLink>
        ))}
        {user?.role === "SECURITY_ADMIN" && (
          <NavLink
            to="/security"
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-2xl px-3.5 py-2.5 text-sm font-medium transition-colors ${
                isActive ? "bg-ink text-paper" : "text-ink-soft hover:bg-line-soft hover:text-ink"
              }`
            }
          >
            {navIcon.security}
            Security
          </NavLink>
        )}
        {user?.role === "SECURITY_ADMIN" && (
          <NavLink
            to="/audit-log"
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-2xl px-3.5 py-2.5 text-sm font-medium transition-colors ${
                isActive ? "bg-ink text-paper" : "text-ink-soft hover:bg-line-soft hover:text-ink"
              }`
            }
          >
            {navIcon.audit}
            Audit log
          </NavLink>
        )}
        {user?.role === "SECURITY_ADMIN" && (
          <NavLink
            to="/team"
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-2xl px-3.5 py-2.5 text-sm font-medium transition-colors ${
                isActive ? "bg-ink text-paper" : "text-ink-soft hover:bg-line-soft hover:text-ink"
              }`
            }
          >
            {navIcon.team}
            Team
          </NavLink>
        )}
      </nav>

      {user?.role === "SECURITY_ADMIN" && recentClients.length > 0 && (
        <div>
          <p className="mb-2 px-1 text-xs font-semibold uppercase tracking-[0.12em] text-ink-faint">Recent clients</p>
          <div className="flex flex-col gap-0.5">
            {recentClients.map((client) => (
              <NavLink
                key={client.id}
                to={`/clients/${client.id}`}
                className="flex items-center gap-2.5 rounded-xl px-3.5 py-2 text-sm text-ink-soft transition-colors hover:bg-line-soft hover:text-ink"
              >
                <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-ink/30" />
                <span className="truncate">{client.name}</span>
              </NavLink>
            ))}
          </div>
        </div>
      )}

    </aside>
  );
}

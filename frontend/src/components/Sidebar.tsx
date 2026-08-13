import { NavLink } from "react-router-dom";
import { useAuth } from "../lib/auth";

function Logomark() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 L21 6 V12 C21 17 17.5 20.5 12 22 C6.5 20.5 3 17 3 12 V6 Z" fill="currentColor" />
      <path d="M8.5 12 L11 14.5 L16 9" stroke="var(--color-paper)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const navIcon = {
  dashboard: (
    <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
      <rect x="3" y="3" width="8" height="8" rx="2.5" fill="currentColor" />
      <rect x="13" y="3" width="8" height="5" rx="2.5" fill="currentColor" opacity="0.4" />
      <rect x="13" y="10" width="8" height="11" rx="2.5" fill="currentColor" opacity="0.4" />
      <rect x="3" y="13" width="8" height="8" rx="2.5" fill="currentColor" opacity="0.4" />
    </svg>
  ),
  clients: (
    <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
      <circle cx="9" cy="8" r="3.4" fill="currentColor" />
      <path d="M3 20c0-3.6 2.7-6 6-6s6 2.4 6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
      <circle cx="18" cy="9" r="2.6" fill="currentColor" opacity="0.45" />
      <path d="M21.5 20c0-2.8-1.8-4.8-4-5.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.45" fill="none" />
    </svg>
  ),
  audit: (
    <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
      <rect x="4" y="3" width="16" height="18" rx="2.5" stroke="currentColor" strokeWidth="1.8" fill="none" />
      <path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  ),
  team: (
    <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
      <circle cx="8" cy="8" r="3" fill="currentColor" />
      <circle cx="16" cy="8" r="3" fill="currentColor" opacity="0.45" />
      <path d="M2.5 20c0-3.3 2.5-5.5 5.5-5.5s5.5 2.2 5.5 5.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
      <path d="M12.5 14.7c2.7.3 4.5 2.4 4.5 5.3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.45" fill="none" />
    </svg>
  ),
  security: (
    <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
      <path d="M12 2 L20 5.5 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V5.5 Z" fill="currentColor" opacity="0.15" stroke="currentColor" strokeWidth="1.6" />
      <path d="M8.5 12 L11 14.5 L15.5 9" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
};

const links = [
  { to: "/", label: "Dashboard", icon: navIcon.dashboard, end: true },
  { to: "/clients", label: "Clients", icon: navIcon.clients, end: false },
];

/** Icon-only rail item with a rounded active pill and a hover tooltip (icon-only nav needs a discoverable label, not just a guessable icon). */
function RailLink({ to, label, icon, end }: { to: string; label: string; icon: React.ReactNode; end?: boolean }) {
  return (
    <NavLink to={to} end={end} className="group relative flex justify-center" aria-label={label}>
      {({ isActive }) => (
        <>
          <span
            className={`flex h-11 w-11 items-center justify-center rounded-2xl transition-colors ${
              isActive ? "bg-ink text-paper" : "text-ink-soft hover:bg-line-soft hover:text-ink"
            }`}
          >
            {icon}
          </span>
          <span
            className="pointer-events-none absolute left-full top-1/2 z-20 ml-3 -translate-y-1/2 whitespace-nowrap rounded-lg bg-ink px-2.5 py-1.5 text-xs font-medium text-paper opacity-0 shadow-[var(--shadow-lift)] transition-opacity duration-150 group-hover:opacity-100"
          >
            {label}
          </span>
        </>
      )}
    </NavLink>
  );
}

export function Sidebar() {
  const { user } = useAuth();

  return (
    <aside className="flex h-full w-[76px] shrink-0 flex-col items-center gap-7 rounded-[var(--radius-card)] border border-line bg-[color:var(--color-surface-glass)] py-6 shadow-[var(--shadow-lift)] backdrop-blur-2xl backdrop-saturate-150">
      <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-ink text-paper">
        <Logomark />
      </span>

      <nav className="flex flex-1 flex-col items-center gap-2">
        {links.map((link) => (
          <RailLink key={link.to} {...link} />
        ))}
        {user?.role === "SECURITY_ADMIN" && <RailLink to="/security" label="Security" icon={navIcon.security} />}
        {user?.role === "SECURITY_ADMIN" && <RailLink to="/audit-log" label="Audit log" icon={navIcon.audit} />}
        {user?.role === "SECURITY_ADMIN" && <RailLink to="/team" label="Team" icon={navIcon.team} />}
      </nav>
    </aside>
  );
}

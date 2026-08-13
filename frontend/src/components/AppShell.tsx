import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { Sidebar } from "./Sidebar";
import { Texture } from "./Texture";
import type { Role } from "../lib/types";

export function AppShell({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  // Clerk resolves asynchronously (unlike the old synchronous localStorage
  // check) — without this, a signed-in user would flash-redirect to /login
  // every reload while their session/role is still resolving.
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;

  return (
    <div className="flex min-h-screen gap-6 p-6">
      <Texture />
      <Sidebar />
      <main className="min-w-0 flex-1">
        <div className="mx-auto flex max-w-6xl flex-col gap-6">{children}</div>
      </main>
    </div>
  );
}

export function RequireRole({ roles, children }: { roles: Role[]; children: ReactNode }) {
  const { user } = useAuth();
  if (!user || !roles.includes(user.role)) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 rounded-3xl border border-dashed border-line py-24 text-center">
        <p className="font-semibold text-ink">You don't have access to this page</p>
        <p className="text-sm text-ink-faint">This area is restricted to {roles.join(" / ").toLowerCase()}.</p>
      </div>
    );
  }
  return <>{children}</>;
}

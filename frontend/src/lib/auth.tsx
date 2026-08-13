import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useAuth as useClerkAuth, useUser } from "@clerk/clerk-react";
import { api, ApiError, setClerkTokenGetter } from "./api";
import type { AuthUser } from "./types";

interface AuthContextValue {
  user: AuthUser | null;
  logout: () => void;
  loading: boolean;
  // True when Clerk sign-in succeeded but no matching row exists in our own
  // User table (see src/middleware/auth.ts) — a real, distinct state from
  // "not signed in", since the person authenticated fine, they just haven't
  // been given a role in Enforcer yet.
  notProvisioned: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { isLoaded, isSignedIn, getToken, signOut } = useClerkAuth();
  const { user: clerkUser } = useUser();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [resolving, setResolving] = useState(true);
  const [notProvisioned, setNotProvisioned] = useState(false);

  // Every request goes through this to attach a fresh Clerk session token
  // (see lib/api.ts) — swapped to null on sign-out so nothing leaks a stale one.
  useEffect(() => {
    setClerkTokenGetter(isSignedIn ? () => getToken() : null);
  }, [isSignedIn, getToken]);

  useEffect(() => {
    if (!isLoaded) return;
    if (!isSignedIn) {
      setUser(null);
      setNotProvisioned(false);
      setResolving(false);
      return;
    }
    setResolving(true);
    api
      .get<AuthUser>("/auth/me")
      .then((fresh) => {
        setUser(fresh);
        setNotProvisioned(false);
      })
      .catch((err) => {
        setUser(null);
        setNotProvisioned(err instanceof ApiError && err.status === 403);
      })
      .finally(() => setResolving(false));
    // clerkUser?.id in deps so switching accounts (not just sign-in state)
    // re-resolves who the app thinks you are.
  }, [isLoaded, isSignedIn, clerkUser?.id]);

  const logout = useCallback(() => {
    void signOut();
  }, [signOut]);

  const value = useMemo(
    () => ({ user, logout, loading: !isLoaded || resolving, notProvisioned }),
    [user, logout, isLoaded, resolving, notProvisioned]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

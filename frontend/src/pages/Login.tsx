import { SignIn } from "@clerk/clerk-react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { Texture } from "../components/Texture";

function Logomark() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 L21 6 V12 C21 17 17.5 20.5 12 22 C6.5 20.5 3 17 3 12 V6 Z" fill="currentColor" />
      <path d="M8.5 12 L11 14.5 L16 9" stroke="var(--color-paper)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function Login() {
  const { user, loading, notProvisioned } = useAuth();

  if (loading) return null;
  if (user) return <Navigate to="/" replace />;

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 p-6">
      <Texture />
      <div className="flex flex-col items-center text-center">
        <span className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-ink text-paper">
          <Logomark />
        </span>
        <h1 className="text-xl font-extrabold tracking-tight text-ink">Sign in to Jupiter</h1>
        <p className="mt-1.5 text-sm text-ink-faint">Encrypted assessment records, only for authorized accounts.</p>
      </div>

      {notProvisioned && (
        <p className="max-w-sm rounded-2xl bg-[color:var(--color-risk-critical)]/10 px-4 py-3 text-center text-sm text-[color:var(--color-risk-critical)]">
          You're signed in, but this account isn't set up in Jupiter yet. Ask an administrator to add your email.
        </p>
      )}

      <SignIn
        routing="virtual"
        appearance={{
          variables: {
            colorPrimary: "#171614",
            colorBackground: "#ffffff",
            colorText: "#171614",
            colorTextSecondary: "#8c8a84",
            colorInputBackground: "#f2f1ee",
            borderRadius: "1rem",
            fontFamily: "var(--font-sans, inherit)",
          },
          elements: {
            card: "shadow-[var(--shadow-lift)] border border-[color:var(--color-line)] rounded-[1.75rem]",
            footer: "hidden",
          },
        }}
      />
    </div>
  );
}

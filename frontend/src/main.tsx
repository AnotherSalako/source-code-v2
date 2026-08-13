import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ClerkProvider } from "@clerk/clerk-react";
import * as Sentry from "@sentry/react";
import "./index.css";
import App from "./App.tsx";

const CLERK_PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;
if (!CLERK_PUBLISHABLE_KEY) {
  throw new Error("Missing VITE_CLERK_PUBLISHABLE_KEY — set it in frontend/.env");
}

// Optional, same as the backend's src/config/sentry.ts — unset means this is
// a no-op, so a crash is only visible in the browser console, same as always.
const SENTRY_DSN = import.meta.env.VITE_SENTRY_DSN;
if (SENTRY_DSN) {
  Sentry.init({ dsn: SENTRY_DSN, tracesSampleRate: 0.1 });
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Sentry.ErrorBoundary fallback={<ErrorFallback />}>
      <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY} signInUrl="/login" afterSignOutUrl="/login">
        <App />
      </ClerkProvider>
    </Sentry.ErrorBoundary>
  </StrictMode>
);

function ErrorFallback() {
  return (
    <div className="flex h-screen items-center justify-center bg-paper px-6 text-center">
      <div>
        <p className="text-lg font-semibold text-ink">Something went wrong.</p>
        <p className="mt-2 text-sm text-ink-soft">Refresh the page — this has been reported.</p>
      </div>
    </div>
  );
}

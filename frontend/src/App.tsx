import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./lib/auth";
import { AppShell, RequireRole } from "./components/AppShell";
import Login from "./pages/Login";
import Dashboard from "./pages/dashboard/Dashboard";
import ClientsList from "./pages/clients/ClientsList";
import ClientDetail from "./pages/clients/ClientDetail";
import EngagementDetail from "./pages/engagements/EngagementDetail";
import AuditLog from "./pages/audit/AuditLog";
import Team from "./pages/team/Team";
import SecurityOverview from "./pages/security/SecurityOverview";

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <AppShell>
                <Dashboard />
              </AppShell>
            }
          />
          <Route
            path="/clients"
            element={
              <AppShell>
                <ClientsList />
              </AppShell>
            }
          />
          <Route
            path="/clients/:clientId"
            element={
              <AppShell>
                <ClientDetail />
              </AppShell>
            }
          />
          <Route
            path="/engagements/:engagementId"
            element={
              <AppShell>
                <EngagementDetail />
              </AppShell>
            }
          />
          <Route
            path="/audit-log"
            element={
              <AppShell>
                <RequireRole roles={["SECURITY_ADMIN"]}>
                  <AuditLog />
                </RequireRole>
              </AppShell>
            }
          />
          <Route
            path="/team"
            element={
              <AppShell>
                <RequireRole roles={["SECURITY_ADMIN"]}>
                  <Team />
                </RequireRole>
              </AppShell>
            }
          />
          <Route
            path="/security"
            element={
              <AppShell>
                <RequireRole roles={["SECURITY_ADMIN"]}>
                  <SecurityOverview />
                </RequireRole>
              </AppShell>
            }
          />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

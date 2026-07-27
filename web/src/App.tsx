import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, PublicOnly, RequireAuth, SetupOnly } from "./auth";
import { Layout } from "./components/Layout";
import { AuditPage } from "./pages/Audit";
import { ClientSetupPage } from "./pages/ClientSetup";
import { DashboardPage } from "./pages/Dashboard";
import { HealthPage } from "./pages/Health";
import { LoginPage } from "./pages/Login";
import { LogsPage } from "./pages/Logs";
import { ObjectsPage } from "./pages/Objects";
import {
  PolicyEditorPage,
  PolicyListPage,
  PolicySimulatePage,
} from "./pages/Policy";
import {
  SettingsLayout,
  GeneralSettings,
  UsersSettings,
  CertsSettings,
  BlockPagesSettings,
  ExportSettings,
} from "./pages/Settings";
import { SetupPage } from "./pages/Setup";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route
            path="/setup"
            element={
              <SetupOnly>
                <SetupPage />
              </SetupOnly>
            }
          />
          <Route
            path="/login"
            element={
              <PublicOnly>
                <LoginPage />
              </PublicOnly>
            }
          />

          <Route
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="health" element={<HealthPage />} />
            <Route path="policy" element={<PolicyListPage />} />
            <Route path="policy/new" element={<PolicyEditorPage />} />
            <Route path="policy/simulate" element={<PolicySimulatePage />} />
            <Route path="policy/:id" element={<PolicyEditorPage />} />
            <Route path="objects" element={<ObjectsPage />} />
            <Route path="logs" element={<LogsPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="client-setup" element={<ClientSetupPage />} />
            <Route path="settings" element={<SettingsLayout />}>
              <Route index element={<GeneralSettings />} />
              <Route path="users" element={<UsersSettings />} />
              <Route path="certificates" element={<CertsSettings />} />
              <Route path="block-pages" element={<BlockPagesSettings />} />
              <Route path="export" element={<ExportSettings />} />
            </Route>
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import { AuthProvider } from "./context/AuthContext";
import { SyncJobProvider } from "./context/SyncJobContext";
import ProtectedRoute from "./components/ProtectedRoute";
import LoginPage from "./pages/LoginPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import HealthPage from "./pages/HealthPage";
import DownloadStatsPage from "./pages/DownloadStatsPage";
import DashboardLayout from "./layouts/DashboardLayout";
import PackageList from "./components/PackageList";
import UploadForm from "./components/UploadForm";
import ClientSetupPage from "./pages/ClientSetupPage";
import ImportPage from "./pages/ImportPage";
import SourcesPage from "./pages/SourcesPage";
import SecurityPage from "./pages/SecurityPage";
import DashboardPage from "./pages/DashboardPage";
import DistributionsPage from "./pages/DistributionsPage";
import SettingsPage from "./pages/SettingsPage";
import UsersPage from "./pages/UsersPage";
import SecurityReportPage from "./pages/SecurityReportPage";
import AuditPage from "./pages/AuditPage";
import LogsPage from "./pages/LogsPage";
import DockerfilePage from "./pages/DockerfilePage";
import PromotionsPage from "./pages/PromotionsPage";
import GroupsPage from "./pages/GroupsPage";
import RolesPage from "./pages/RolesPage";
import TemplatesPage from "./pages/TemplatesPage";

export default function App() {
  return (
    <AuthProvider>
      <SyncJobProvider>
      <BrowserRouter>
        <Toaster position="top-right" toastOptions={{ duration: 4000 }} />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/security/report" element={
            <ProtectedRoute><SecurityReportPage /></ProtectedRoute>
          } />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <DashboardLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="packages" element={<PackageList />} />
            <Route path="upload" element={<UploadForm />} />
            <Route path="setup" element={<ClientSetupPage />} />
            <Route path="import" element={<ImportPage />} />
            <Route path="sources" element={<SourcesPage />} />
            <Route path="security" element={<SecurityPage />} />
            <Route path="distributions" element={<DistributionsPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="users"     element={<UsersPage />} />
            <Route path="audit"     element={<AuditPage />} />
            <Route path="supervision" element={<HealthPage />} />
            <Route path="downloads" element={<DownloadStatsPage />} />
            <Route path="logs"        element={<LogsPage />} />
            <Route path="dockerfile"  element={<DockerfilePage />} />
            <Route path="promotions"  element={<PromotionsPage />} />
            <Route path="groups"       element={<GroupsPage />} />
            <Route path="roles"        element={<RolesPage />} />
            <Route path="templates"   element={<TemplatesPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
      </SyncJobProvider>
    </AuthProvider>
  );
}

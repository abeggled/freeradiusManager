import { Navigate, Route, Routes, useNavigate } from "react-router-dom";

import { useMe } from "@/api/hooks";
import { Layout } from "@/components/Layout";
import { Spinner } from "@/components/ui";
import { AccountsPage } from "@/pages/Accounts";
import { AuditPage } from "@/pages/Audit";
import { AuthLogPage } from "@/pages/AuthLog";
import { DashboardPage } from "@/pages/Dashboard";
import { DeviceDetailPage } from "@/pages/DeviceDetail";
import { DevicesPage } from "@/pages/Devices";
import { DiagnosePage } from "@/pages/Diagnose";
import { GroupsPage } from "@/pages/Groups";
import { LoginPage } from "@/pages/Login";
import { NasPage } from "@/pages/Nas";
import { ProfilePage } from "@/pages/Profile";
import { SessionsPage } from "@/pages/Sessions";
import { SettingsPage } from "@/pages/Settings";
import { UserDetailPage } from "@/pages/UserDetail";
import { UsersPage } from "@/pages/Users";

export function App() {
  const me = useMe();
  const navigate = useNavigate();

  if (me.isLoading) return <Spinner />;

  if (!me.data) {
    return (
      <Routes>
        <Route
          path="*"
          element={
            <LoginPage
              onAuthenticated={() => {
                void me.refetch();
                navigate("/");
              }}
            />
          }
        />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route element={<Layout account={me.data} />}>
        <Route index element={<DashboardPage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="users/:username" element={<UserDetailPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/:mac" element={<DeviceDetailPage />} />
        <Route path="groups" element={<GroupsPage />} />
        <Route path="nas" element={<NasPage />} />
        <Route path="sessions" element={<SessionsPage />} />
        <Route path="authlog" element={<AuthLogPage />} />
        <Route path="diagnose" element={<DiagnosePage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="accounts" element={<AccountsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="login" element={<Navigate to="/" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

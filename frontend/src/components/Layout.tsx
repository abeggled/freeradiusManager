import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useLogout } from "@/api/hooks";
import type { Account } from "@/api/types";
import { useI18n, type Language, type TranslationKey } from "@/i18n";

interface NavEntry {
  to: string;
  label: TranslationKey;
  roles?: Account["role"][];
}

const ENTRIES: NavEntry[] = [
  { to: "/", label: "nav.dashboard" },
  { to: "/users", label: "nav.users" },
  { to: "/devices", label: "nav.devices" },
  { to: "/groups", label: "nav.groups" },
  { to: "/nas", label: "nav.nas", roles: ["administrator", "auditor"] },
  { to: "/sessions", label: "nav.sessions" },
  { to: "/authlog", label: "nav.authlog" },
  { to: "/audit", label: "nav.audit" },
  { to: "/accounts", label: "nav.accounts", roles: ["administrator"] },
  { to: "/settings", label: "nav.settings", roles: ["administrator"] },
];

export function Layout({ account }: { account: Account }) {
  const { t, language, setLanguage } = useI18n();
  const logout = useLogout();
  const navigate = useNavigate();

  const entries = ENTRIES.filter((entry) => !entry.roles || entry.roles.includes(account.role));

  return (
    <div className="layout">
      <aside>
        <div className="brand">
          <strong>{t("app.title")}</strong>
          <small>{t("app.subtitle")}</small>
        </div>
        <nav>
          {entries.map((entry) => (
            <NavLink key={entry.to} to={entry.to} end={entry.to === "/"}>
              {t(entry.label)}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <NavLink to="/profile">{t("nav.profile")}</NavLink>
          <div className="account">
            <span>{account.display_name || account.username}</span>
            <small>{t(`accounts.role.${account.role}` as TranslationKey)}</small>
          </div>
          <label className="language">
            <span>{t("common.language")}</span>
            <select
              value={language}
              onChange={(event) => setLanguage(event.target.value as Language)}
            >
              <option value="de">Deutsch</option>
              <option value="en">English</option>
            </select>
          </label>
          <button
            type="button"
            onClick={() => {
              logout.mutate(undefined, { onSuccess: () => navigate("/login") });
            }}
          >
            {t("nav.logout")}
          </button>
        </div>
      </aside>
      <main>
        <Outlet />
      </main>
    </div>
  );
}

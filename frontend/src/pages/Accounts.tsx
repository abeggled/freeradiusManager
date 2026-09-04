import { useState } from "react";

import {
  useAccounts,
  useCreateAccount,
  useDeleteAccount,
  useLinkOidc,
  useUpdateAccount,
} from "@/api/hooks";
import type { Account, Role } from "@/api/types";
import { ConfirmDialog, ErrorBox, Field, Modal, Pagination, Spinner } from "@/components/ui";
import { useI18n, type TranslationKey } from "@/i18n";
import { formatDateTime } from "@/lib/format";

const LIMIT = 50;
const ROLES: Role[] = ["administrator", "operator", "auditor"];

export function AccountsPage() {
  const { t, language } = useI18n();
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<Account | null>(null);
  const [confirmTotpReset, setConfirmTotpReset] = useState<Account | null>(null);
  const [confirmDeactivate, setConfirmDeactivate] = useState<Account | null>(null);
  const [confirmRole, setConfirmRole] = useState<{ account: Account; role: Role } | null>(null);
  const [linking, setLinking] = useState<Account | null>(null);

  const { data, isLoading, error } = useAccounts({ limit: LIMIT, offset });
  const update = useUpdateAccount();
  const remove = useDeleteAccount();

  return (
    <section>
      <header className="page-header">
        <h1>{t("accounts.title")}</h1>
        <button type="button" className="primary" onClick={() => setCreating(true)}>
          {t("accounts.new")}
        </button>
      </header>

      <ErrorBox error={error ?? update.error ?? remove.error} />
      {isLoading ? (
        <Spinner />
      ) : (
        <>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t("login.username")}</th>
                  <th>{t("accounts.displayName")}</th>
                  <th>{t("accounts.role")}</th>
                  <th>{t("accounts.active")}</th>
                  <th>{t("accounts.totp")}</th>
                  <th>{t("accounts.oidc")}</th>
                  <th>{t("accounts.lastLogin")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((account) => (
                  <tr key={account.id}>
                    <td>{account.username}</td>
                    <td>{account.display_name ?? "–"}</td>
                    <td>
                      <select
                        value={account.role}
                        onChange={(event) => {
                          const next = event.target.value as Role;
                          // Eine Rollenänderung beendet die Sitzung des Kontos;
                          // eine Einschränkung wird deshalb bestätigt.
                          if (ROLES.indexOf(next) > ROLES.indexOf(account.role)) {
                            setConfirmRole({ account, role: next });
                            return;
                          }
                          update.mutate({ id: account.id, body: { role: next } });
                        }}
                      >
                        {ROLES.map((role) => (
                          <option key={role} value={role}>
                            {t(`accounts.role.${role}` as TranslationKey)}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={t("accounts.active")}
                        checked={account.is_active}
                        onChange={(event) => {
                          // Deaktivieren beendet laufende Sitzungen und lässt
                          // sich vom Betroffenen nicht rückgängig machen.
                          if (!event.target.checked) {
                            setConfirmDeactivate(account);
                            return;
                          }
                          update.mutate({ id: account.id, body: { is_active: true } });
                        }}
                      />
                    </td>
                    <td>{account.totp_enabled ? t("common.yes") : t("common.no")}</td>
                    <td>
                      <button type="button" className="link" onClick={() => setLinking(account)}>
                        {account.oidc_subject ?? t("accounts.oidcLink")}
                      </button>
                    </td>
                    <td>{formatDateTime(account.last_login_at, language)}</td>
                    <td className="row-actions">
                      <button type="button" onClick={() => setConfirmTotpReset(account)}>
                        {t("accounts.resetTotp")}
                      </button>
                      <button
                        type="button"
                        className="danger"
                        onClick={() => setConfirmDelete(account)}
                      >
                        {t("common.delete")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination
            total={data?.meta.total ?? 0}
            limit={LIMIT}
            offset={offset}
            onChange={setOffset}
          />
        </>
      )}

      {creating ? <CreateAccountDialog onClose={() => setCreating(false)} /> : null}
      {linking ? <OidcLinkDialog account={linking} onClose={() => setLinking(null)} /> : null}

      {confirmRole ? (
        <ConfirmDialog
          title={t("accounts.role")}
          message={t("accounts.roleConfirm", {
            name: confirmRole.account.username,
            role: t(`accounts.role.${confirmRole.role}` as TranslationKey),
          })}
          onConfirm={() =>
            update.mutate(
              { id: confirmRole.account.id, body: { role: confirmRole.role } },
              { onSuccess: () => setConfirmRole(null) },
            )
          }
          onCancel={() => setConfirmRole(null)}
          busy={update.isPending}
        />
      ) : null}

      {confirmDeactivate ? (
        <ConfirmDialog
          title={t("accounts.deactivate")}
          message={t("accounts.deactivateConfirm", { name: confirmDeactivate.username })}
          onConfirm={() =>
            update.mutate(
              { id: confirmDeactivate.id, body: { is_active: false } },
              { onSuccess: () => setConfirmDeactivate(null) },
            )
          }
          onCancel={() => setConfirmDeactivate(null)}
          busy={update.isPending}
        />
      ) : null}

      {confirmTotpReset ? (
        <ConfirmDialog
          title={t("accounts.resetTotp")}
          message={t("accounts.resetTotpConfirm", { name: confirmTotpReset.username })}
          onConfirm={() =>
            update.mutate(
              { id: confirmTotpReset.id, body: { reset_totp: true } },
              { onSuccess: () => setConfirmTotpReset(null) },
            )
          }
          onCancel={() => setConfirmTotpReset(null)}
          busy={update.isPending}
        />
      ) : null}

      {confirmDelete ? (
        <ConfirmDialog
          title={t("common.delete")}
          message={`${confirmDelete.username}?`}
          onConfirm={() =>
            remove.mutate(confirmDelete.id, { onSuccess: () => setConfirmDelete(null) })
          }
          onCancel={() => setConfirmDelete(null)}
          busy={remove.isPending}
        />
      ) : null}
    </section>
  );
}

/** Verknüpft ein bestehendes Konto mit einer OIDC-Identität (FR-10). */
function OidcLinkDialog({ account, onClose }: { account: Account; onClose: () => void }) {
  const { t } = useI18n();
  const link = useLinkOidc();
  const [subject, setSubject] = useState(account.oidc_subject ?? "");

  return (
    <Modal
      title={t("accounts.oidcLink")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          {account.oidc_subject ? (
            <button
              type="button"
              className="danger"
              onClick={() =>
                link.mutate({ id: account.id, subject: null }, { onSuccess: onClose })
              }
            >
              {t("accounts.oidcUnlink")}
            </button>
          ) : null}
          <button
            type="button"
            className="primary"
            disabled={!subject.trim() || link.isPending}
            onClick={() =>
              link.mutate({ id: account.id, subject: subject.trim() }, { onSuccess: onClose })
            }
          >
            {t("common.save")}
          </button>
        </>
      }
    >
      <ErrorBox error={link.error} />
      <Field label={t("accounts.oidcSubject")} hint={t("accounts.oidcHint")}>
        {(id) => (
          <input id={id} value={subject} onChange={(event) => setSubject(event.target.value)} />
        )}
      </Field>
    </Modal>
  );
}

function CreateAccountDialog({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const create = useCreateAccount();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("auditor");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");

  return (
    <Modal
      title={t("accounts.new")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button
            type="submit"
            form="create-account"
            className="primary"
            disabled={create.isPending}
          >
            {t("common.create")}
          </button>
        </>
      }
    >
      <form
        id="create-account"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            {
              username,
              password,
              role,
              email: email || null,
              display_name: displayName || null,
            },
            { onSuccess: onClose },
          );
        }}
      >
        <ErrorBox error={create.error} />
        <Field label={t("login.username")} required>
          {(id) => (
            <input
              id={id}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t("login.password")} required>
          {(id) => (
            <input
              id={id}
              type="password"
              minLength={12}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t("accounts.role")}>
          {(id) => (
            <select id={id} value={role} onChange={(event) => setRole(event.target.value as Role)}>
              {ROLES.map((entry) => (
                <option key={entry} value={entry}>
                  {t(`accounts.role.${entry}` as TranslationKey)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t("accounts.displayName")}>
          {(id) => (
            <input
              id={id}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          )}
        </Field>
        <Field label={t("accounts.email")}>
          {(id) => (
            <input
              id={id}
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          )}
        </Field>
      </form>
    </Modal>
  );
}

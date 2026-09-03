import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  useDeleteUser,
  useGroups,
  useSetUserPassword,
  useToggleUser,
  useUpdateUser,
  useUser,
} from "@/api/hooks";
import {
  ConfirmDialog,
  ErrorBox,
  Field,
  Modal,
  Spinner,
  StatusBadge,
  WarningList,
} from "@/components/ui";
import { usePermissions } from "@/hooks/usePermissions";
import { useI18n } from "@/i18n";
import { formatDateTime, toIso, toLocalInput } from "@/lib/format";

export function UserDetailPage() {
  const { username = "" } = useParams();
  const { t, language } = useI18n();
  const navigate = useNavigate();
  const { canWrite } = usePermissions();

  const { data, isLoading, error } = useUser(username);
  const update = useUpdateUser(username);
  const toggle = useToggleUser();
  const remove = useDeleteUser();
  const setPassword = useSetUserPassword(username);
  const groups = useGroups();

  const [showPassword, setShowPassword] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [password, setPasswordValue] = useState("");
  const [vlan, setVlan] = useState<string | null>(null);
  const [expires, setExpires] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [owner, setOwner] = useState<string | null>(null);
  const [memberships, setMemberships] = useState<string[] | null>(null);

  if (isLoading) return <Spinner />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  const save = () => {
    update.mutate({
      vlan: vlan ?? undefined,
      clear_vlan: vlan === "",
      expires_at: expires ? toIso(expires) : undefined,
      clear_expiry: expires === "",
      // Alle Mitgliedschaften werden gemeinsam gesendet: das Backend ersetzt die
      // Sammlung vollständig, eine einzelne Auswahl würde die übrigen löschen.
      groups:
        memberships === null
          ? undefined
          : memberships.map((groupname) => ({
              groupname,
              priority: data.memberships.find((m) => m.groupname === groupname)?.priority ?? 1,
            })),
      meta: {
        note: note ?? undefined,
        owner: owner ?? undefined,
      },
    });
  };

  return (
    <section>
      <header className="page-header">
        <div>
          <Link to="/users" className="link">
            ← {t("users.title")}
          </Link>
          <h1>
            {data.username} <StatusBadge status={data.status} />
          </h1>
          {!data.has_metadata ? <p className="muted">{t("users.noMetadata")}</p> : null}
        </div>
        <div className="actions">
          <Link className="button" to={`/diagnose?subject=${encodeURIComponent(data.username)}`}>
            {t("users.diagnose")}
          </Link>
          {canWrite ? (
            <>
          <button type="button" onClick={() => setShowPassword(true)}>
            {t("users.setPassword")}
          </button>
          <button
            type="button"
            onClick={() =>
              toggle.mutate({ username: data.username, disabled: data.status !== "disabled" })
            }
          >
            {data.status === "disabled" ? t("users.enable") : t("users.disable")}
          </button>
          <button type="button" className="danger" onClick={() => setConfirmDelete(true)}>
            {t("common.delete")}
          </button>
            </>
          ) : null}
        </div>
      </header>

      <ErrorBox error={update.error ?? toggle.error ?? remove.error} />
      <WarningList warnings={data.warnings} />

      <div className="columns">
        <div className="card">
          <h2>{t("common.details")}</h2>
          <dl>
            <dt>{t("users.credentialType")}</dt>
            <dd>{data.credential_type ?? "–"}</dd>
            <dt>{t("users.activeSessions")}</dt>
            <dd>{data.active_sessions}</dd>
            <dt>{t("users.lastAuth")}</dt>
            <dd>
              {formatDateTime(data.last_auth, language)}
              {data.last_auth_reply ? ` (${data.last_auth_reply})` : ""}
            </dd>
          </dl>

          <Field label={t("users.vlan")}>
            {(id) => (
              <input
                id={id}
                value={vlan ?? data.vlan ?? ""}
                onChange={(event) => setVlan(event.target.value)}
              />
            )}
          </Field>
          <Field label={t("users.groups")} hint={t("users.groupsHint")}>
            {(id) => (
              <select
                id={id}
                multiple
                size={Math.min(6, Math.max(3, (groups.data ?? []).length))}
                value={memberships ?? data.groups}
                onChange={(event) =>
                  setMemberships(
                    Array.from(event.target.selectedOptions).map((option) => option.value),
                  )
                }
              >
                {(groups.data ?? []).map((entry) => (
                  <option key={entry.groupname} value={entry.groupname}>
                    {entry.groupname}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label={t("users.expires")}>
            {(id) => (
              <input
                id={id}
                type="datetime-local"
                value={expires ?? toLocalInput(data.expires_at)}
                onChange={(event) => setExpires(event.target.value)}
              />
            )}
          </Field>
          <Field label={t("common.owner")}>
            {(id) => (
              <input
                id={id}
                value={owner ?? data.owner ?? ""}
                onChange={(event) => setOwner(event.target.value)}
              />
            )}
          </Field>
          <Field label={t("common.note")}>
            {(id) => (
              <textarea
                id={id}
                value={note ?? data.note ?? ""}
                onChange={(event) => setNote(event.target.value)}
              />
            )}
          </Field>
          {canWrite ? (
            <button type="button" className="primary" onClick={save} disabled={update.isPending}>
              {t("common.save")}
            </button>
          ) : null}
        </div>

        <div className="card">
          <h2>{t("users.checkAttributes")}</h2>
          <AttributeTable rows={data.check_attributes} />
          <h2>{t("users.replyAttributes")}</h2>
          <AttributeTable rows={data.reply_attributes} />
        </div>
      </div>

      {showPassword ? (
        <Modal
          title={t("users.setPassword")}
          onClose={() => setShowPassword(false)}
          footer={
            <>
              <button type="button" onClick={() => setShowPassword(false)}>
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="primary"
                disabled={!password || setPassword.isPending}
                onClick={() =>
                  setPassword.mutate(
                    { password },
                    {
                      onSuccess: () => {
                        setShowPassword(false);
                        setPasswordValue("");
                      },
                    },
                  )
                }
              >
                {t("common.save")}
              </button>
            </>
          }
        >
          <ErrorBox error={setPassword.error} />
          <Field label={t("users.password")} hint={t("users.credentialTypeHint")} required>
            {(id) => (
              <input
                id={id}
                type="password"
                value={password}
                onChange={(event) => setPasswordValue(event.target.value)}
              />
            )}
          </Field>
        </Modal>
      ) : null}

      {confirmDelete ? (
        <ConfirmDialog
          title={t("common.delete")}
          message={t("users.deleteConfirm", { name: data.username })}
          onConfirm={() =>
            remove.mutate(data.username, { onSuccess: () => navigate("/users") })
          }
          onCancel={() => setConfirmDelete(false)}
          busy={remove.isPending}
        />
      ) : null}
    </section>
  );
}

function AttributeTable({
  rows,
}: {
  rows: { id: number; attribute: string; op: string; value: string }[];
}) {
  const { t } = useI18n();
  if (rows.length === 0) return <p className="muted">{t("common.empty")}</p>;
  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>{t("groups.attribute")}</th>
            <th>{t("groups.operator")}</th>
            <th>{t("groups.value")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>{row.attribute}</td>
              <td>
                <code>{row.op}</code>
              </td>
              <td>{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

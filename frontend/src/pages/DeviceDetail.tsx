import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  useDeleteDevice,
  useDevice,
  useGroups,
  useToggleUser,
  useUpdateDevice,
} from "@/api/hooks";
import { ConfirmDialog, ErrorBox, Field, Spinner, StatusBadge, WarningList } from "@/components/ui";
import { usePermissions } from "@/hooks/usePermissions";
import { useI18n } from "@/i18n";
import { formatDateTime, toIso, toLocalInput } from "@/lib/format";

/** Bearbeiten eines MAB-Geräts inklusive MAC und Inventar-Metadaten (FR-3). */
export function DeviceDetailPage() {
  const { mac = "" } = useParams();
  const { t, language } = useI18n();
  const navigate = useNavigate();
  const { canWrite } = usePermissions();

  const { data, isLoading, error } = useDevice(mac);
  const update = useUpdateDevice(mac);
  const remove = useDeleteDevice();
  const toggle = useToggleUser();
  const groups = useGroups();

  const [draft, setDraft] = useState<Record<string, string>>({});
  const [memberships, setMemberships] = useState<string[] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  if (isLoading) return <Spinner />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  const value = (key: string, fallback: string | null | undefined) =>
    draft[key] ?? fallback ?? "";

  const save = () => {
    update.mutate(
      {
        mac: draft.mac && draft.mac !== data.username ? draft.mac : undefined,
        vlan: draft.vlan ?? undefined,
        clear_vlan: draft.vlan === "",
        expires_at: draft.expires_at ? toIso(draft.expires_at) : undefined,
        clear_expiry: draft.expires_at === "",
        // Vollständige Sammlung senden; eine Einzelauswahl würde die übrigen
        // Mitgliedschaften löschen.
        groups:
          memberships === null
            ? undefined
            : memberships.map((groupname) => ({
                groupname,
                priority:
                  data.memberships.find((m) => m.groupname === groupname)?.priority ?? 1,
              })),
        meta: {
          device_type: draft.device_type ?? undefined,
          location: draft.location ?? undefined,
          inventory_no: draft.inventory_no ?? undefined,
          owner: draft.owner ?? undefined,
          note: draft.note ?? undefined,
        },
      },
      {
        onSuccess: (updated) => {
          setDraft({});
          setMemberships(null);
          if (updated.username !== data.username) {
            navigate(`/devices/${encodeURIComponent(updated.username)}`, { replace: true });
          }
        },
      },
    );
  };

  return (
    <section>
      <header className="page-header">
        <div>
          <Link to="/devices" className="link">
            ← {t("devices.title")}
          </Link>
          <h1>
            {data.username} <StatusBadge status={data.status} />
          </h1>
        </div>
        <div className="actions">
          <Link className="button" to={`/diagnose?subject=${encodeURIComponent(data.username)}`}>
            {t("users.diagnose")}
          </Link>
          {canWrite ? (
            <>
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
            <dt>{t("users.activeSessions")}</dt>
            <dd>{data.active_sessions}</dd>
            <dt>{t("users.lastAuth")}</dt>
            <dd>{formatDateTime(data.last_auth, language)}</dd>
          </dl>

          <Field label={t("devices.mac")}>
            {(id) => (
              <input
                id={id}
                value={value("mac", data.username)}
                onChange={(event) => setDraft({ ...draft, mac: event.target.value })}
              />
            )}
          </Field>
          <Field label={t("devices.type")}>
            {(id) => (
              <input
                id={id}
                value={value("device_type", data.device_type)}
                onChange={(event) => setDraft({ ...draft, device_type: event.target.value })}
              />
            )}
          </Field>
          <Field label={t("common.location")}>
            {(id) => (
              <input
                id={id}
                value={value("location", data.location)}
                onChange={(event) => setDraft({ ...draft, location: event.target.value })}
              />
            )}
          </Field>
          <Field label={t("devices.inventory")}>
            {(id) => (
              <input
                id={id}
                value={value("inventory_no", data.inventory_no)}
                onChange={(event) => setDraft({ ...draft, inventory_no: event.target.value })}
              />
            )}
          </Field>
          <Field label={t("common.owner")}>
            {(id) => (
              <input
                id={id}
                value={value("owner", data.owner)}
                onChange={(event) => setDraft({ ...draft, owner: event.target.value })}
              />
            )}
          </Field>
          <Field label={t("common.note")}>
            {(id) => (
              <textarea
                id={id}
                value={value("note", data.note)}
                onChange={(event) => setDraft({ ...draft, note: event.target.value })}
              />
            )}
          </Field>
        </div>

        <div className="card">
          <h2>{t("users.groups")}</h2>
          <Field label={t("groups.name")} hint={t("users.groupsHint")}>
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
          <Field label={t("users.vlan")}>
            {(id) => (
              <input
                id={id}
                value={value("vlan", data.vlan)}
                onChange={(event) => setDraft({ ...draft, vlan: event.target.value })}
              />
            )}
          </Field>
          <Field label={t("users.expires")}>
            {(id) => (
              <input
                id={id}
                type="datetime-local"
                value={draft.expires_at ?? toLocalInput(data.expires_at)}
                onChange={(event) => setDraft({ ...draft, expires_at: event.target.value })}
              />
            )}
          </Field>
          {canWrite ? (
            <button type="button" className="primary" onClick={save} disabled={update.isPending}>
              {t("common.save")}
            </button>
          ) : null}
        </div>
      </div>

      {confirmDelete ? (
        <ConfirmDialog
          title={t("common.delete")}
          message={t("users.deleteConfirm", { name: data.username })}
          onConfirm={() =>
            remove.mutate(data.username, { onSuccess: () => navigate("/devices") })
          }
          onCancel={() => setConfirmDelete(false)}
          busy={remove.isPending}
        />
      ) : null}
    </section>
  );
}

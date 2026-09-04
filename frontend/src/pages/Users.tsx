import type { ColumnDef } from "@tanstack/react-table";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { buildQuery, download } from "@/api/client";
import {
  useBulkAction,
  useCreateUser,
  useGroups,
  useUsers,
} from "@/api/hooks";
import type { UserListItem } from "@/api/types";
import { DataTable } from "@/components/DataTable";
import {
  ConfirmDialog,
  ErrorBox,
  Field,
  Modal,
  Pagination,
  Spinner,
  StatusBadge,
  WarningList,
} from "@/components/ui";
import { usePermissions } from "@/hooks/usePermissions";
import { useI18n, type TranslationKey } from "@/i18n";
import { formatDateTime, toIso } from "@/lib/format";

import { ImportDialog } from "./ImportDialog";

const LIMIT = 50;

const BULK_ACTIONS = [
  "disable",
  "enable",
  "delete",
  "assign_group",
  "remove_group",
  "set_expiry",
] as const;
type BulkActionName = (typeof BULK_ACTIONS)[number];

export function UsersPage() {
  const { t, language } = useI18n();
  const navigate = useNavigate();
  const { canWrite } = usePermissions();

  const [search, setSearch] = useState("");
  const [group, setGroup] = useState("");
  const [status, setStatus] = useState("");
  const [includeDevices, setIncludeDevices] = useState(false);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [bulk, setBulk] = useState<BulkActionName | "">("");
  const [bulkGroup, setBulkGroup] = useState("");
  const [bulkExpiry, setBulkExpiry] = useState("");
  const [bulkAll, setBulkAll] = useState(false);
  const [confirmBulk, setConfirmBulk] = useState(false);

  // Ein Filterobjekt fuer Liste, Export und Bulk – so treffen Sammelaktionen
  // nie mehr Objekte als angezeigt (FR-8, NFR-4).
  const filters = {
    search: search || undefined,
    group: group || undefined,
    status: status || undefined,
    include_devices: includeDevices,
  };
  const query = { ...filters, limit: LIMIT, offset };

  const { data, isLoading, error } = useUsers(query);

  // Nicht mehr sichtbare Einträge dürfen in einer Sammelaktion nicht
  // mitlaufen: die Bestätigung zeigt nur eine Anzahl, keine Namen.
  useEffect(() => {
    setSelected([]);
    setBulkAll(false);
  }, [search, group, status, includeDevices, offset]);
  const groups = useGroups();
  const bulkAction = useBulkAction();

  const columns = useMemo<ColumnDef<UserListItem, unknown>[]>(
    () => [
      ...(canWrite
        ? [
      {
        id: "select",
        header: () => null,
        cell: ({ row }) => (
          <input
            type="checkbox"
            aria-label={row.original.username}
            checked={selected.includes(row.original.username)}
            onClick={(event) => event.stopPropagation()}
            onChange={(event) =>
              setSelected((current) =>
                event.target.checked
                  ? [...current, row.original.username]
                  : current.filter((name) => name !== row.original.username),
              )
            }
          />
        ),
        enableSorting: false,
      } as ColumnDef<UserListItem, unknown>,
          ]
        : []),
      { accessorKey: "username", header: () => t("users.username") },
      {
        accessorKey: "display_name",
        header: () => t("accounts.displayName"),
        cell: ({ getValue }) => (getValue() as string | null) ?? "–",
      },
      {
        accessorKey: "status",
        header: () => t("users.status"),
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        accessorKey: "groups",
        header: () => t("users.groups"),
        cell: ({ row }) => row.original.groups.join(", ") || "–",
      },
      {
        accessorKey: "owner",
        header: () => t("common.owner"),
        cell: ({ getValue }) => (getValue() as string | null) ?? "–",
      },
      {
        accessorKey: "expires_at",
        header: () => t("users.expires"),
        cell: ({ getValue }) => formatDateTime(getValue() as string | null, language),
      },
    ],
    [canWrite, language, selected, t],
  );

  const affected = bulkAll ? (data?.meta.total ?? 0) : selected.length;

  const runBulk = () => {
    if (!bulk) return;
    bulkAction.mutate(
      {
        body: {
          action: bulk,
          usernames: bulkAll ? [] : selected,
          filter_all: bulkAll,
          groupname: bulkGroup || null,
          expires_at: bulk === "set_expiry" ? toIso(bulkExpiry) : null,
        },
        query: filters,
      },
      {
        onSuccess: () => {
          setSelected([]);
          setConfirmBulk(false);
        },
      },
    );
  };

  return (
    <section>
      <header className="page-header">
        <h1>{t("users.title")}</h1>
        <div className="actions">
          {canWrite ? (
            <button type="button" onClick={() => setShowImport(true)}>
              {t("common.import")}
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => void download(`/users/export${buildQuery(filters)}`, "benutzer.csv")}
          >
            {t("common.export")}
          </button>
          {canWrite ? (
            <button type="button" className="primary" onClick={() => setShowCreate(true)}>
              {t("users.new")}
            </button>
          ) : null}
        </div>
      </header>

      <div className="filters">
        <input
          placeholder={t("common.search")}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
        <select
          value={group}
          onChange={(event) => {
            setGroup(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">{t("users.groups")}: {t("common.all")}</option>
          {(groups.data ?? []).map((entry) => (
            <option key={entry.groupname} value={entry.groupname}>
              {entry.groupname}
            </option>
          ))}
        </select>
        <select
          value={status}
          onChange={(event) => {
            setStatus(event.target.value);
            setOffset(0);
          }}
        >
          <option value="">{t("users.status")}: {t("common.all")}</option>
          <option value="active">{t("status.active")}</option>
          <option value="disabled">{t("status.disabled")}</option>
          <option value="expired">{t("status.expired")}</option>
          <option value="no_credentials">{t("status.no_credentials")}</option>
        </select>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={includeDevices}
            onChange={(event) => setIncludeDevices(event.target.checked)}
          />
          {t("users.includeDevices")}
        </label>
        <button
          type="button"
          onClick={() => {
            setSearch("");
            setGroup("");
            setStatus("");
            setIncludeDevices(false);
            setOffset(0);
          }}
        >
          {t("common.reset")}
        </button>
      </div>

      {canWrite && (selected.length > 0 || bulkAll) && (
        <div className="bulkbar">
          <span>{t("common.selected", { count: affected })}</span>
          <select value={bulk} onChange={(event) => setBulk(event.target.value as BulkActionName)}>
            <option value="">{t("bulk.action")}</option>
            {BULK_ACTIONS.map((action) => (
              <option key={action} value={action}>
                {t(`bulk.${action}` as TranslationKey)}
              </option>
            ))}
          </select>
          {(bulk === "assign_group" || bulk === "remove_group") && (
            <select value={bulkGroup} onChange={(event) => setBulkGroup(event.target.value)}>
              <option value="">{t("groups.name")}</option>
              {(groups.data ?? []).map((entry) => (
                <option key={entry.groupname} value={entry.groupname}>
                  {entry.groupname}
                </option>
              ))}
            </select>
          )}
          {bulk === "set_expiry" && (
            <input
              type="datetime-local"
              value={bulkExpiry}
              onChange={(event) => setBulkExpiry(event.target.value)}
            />
          )}
          <label className="checkbox">
            <input
              type="checkbox"
              checked={bulkAll}
              onChange={(event) => setBulkAll(event.target.checked)}
            />
            {t("bulk.applyToFilter")}
          </label>
          <button
            type="button"
            disabled={
              !bulk ||
              (bulk === "set_expiry" && !bulkExpiry) ||
              ((bulk === "assign_group" || bulk === "remove_group") && !bulkGroup)
            }
            onClick={() => setConfirmBulk(true)}
          >
            {t("common.confirm")}
          </button>
          <button
            type="button"
            onClick={() => {
              setSelected([]);
              setBulkAll(false);
              setBulk("");
            }}
          >
            {t("common.cancel")}
          </button>
        </div>
      )}

      {bulkAction.data ? (
        <p className="alert alert-info">
          {t("bulk.result", {
            succeeded: bulkAction.data.succeeded,
            requested: bulkAction.data.requested,
            failed: bulkAction.data.failed,
          })}
        </p>
      ) : null}

      <ErrorBox error={error ?? bulkAction.error} />
      {isLoading ? (
        <Spinner />
      ) : (
        <>
          <DataTable
            data={data?.items ?? []}
            columns={columns}
            onRowClick={(row) => navigate(`/users/${encodeURIComponent(row.username)}`)}
          />
          <Pagination
            total={data?.meta.total ?? 0}
            limit={LIMIT}
            offset={offset}
            onChange={setOffset}
          />
        </>
      )}

      {showCreate ? <CreateUserDialog onClose={() => setShowCreate(false)} /> : null}
      {showImport ? <ImportDialog kind="user" onClose={() => setShowImport(false)} /> : null}
      {confirmBulk && bulk ? (
        <ConfirmDialog
          title={t("bulk.title")}
          message={t("bulk.confirm", {
            action: t(`bulk.${bulk}` as TranslationKey),
            count: affected,
          })}
          onConfirm={runBulk}
          onCancel={() => setConfirmBulk(false)}
          busy={bulkAction.isPending}
        />
      ) : null}
    </section>
  );
}

function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const create = useCreateUser();
  const groups = useGroups();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [credentialType, setCredentialType] = useState("both");
  const [vlan, setVlan] = useState("");
  const [group, setGroup] = useState("");
  const [expires, setExpires] = useState("");
  const [note, setNote] = useState("");
  const [owner, setOwner] = useState("");

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    create.mutate(
      {
        username,
        password: password || null,
        credential_type: credentialType,
        vlan: vlan || null,
        expires_at: toIso(expires),
        groups: group ? [{ groupname: group, priority: 1 }] : [],
        meta: { note: note || null, owner: owner || null },
      },
      { onSuccess: onClose },
    );
  };

  return (
    <Modal
      title={t("users.new")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" form="create-user" className="primary" disabled={create.isPending}>
            {t("common.create")}
          </button>
        </>
      }
    >
      <form id="create-user" onSubmit={submit}>
        <ErrorBox error={create.error} />
        <Field label={t("users.username")} required>
          {(id) => (
            <input
              id={id}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t("users.password")} required>
          {(id) => (
            <input
              id={id}
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t("users.credentialType")} hint={t("users.credentialTypeHint")}>
          {(id) => (
            <select
              id={id}
              value={credentialType}
              onChange={(event) => setCredentialType(event.target.value)}
            >
              <option value="both">{t("users.credentialType.both")}</option>
              <option value="cleartext">{t("users.credentialType.cleartext")}</option>
              <option value="nt">{t("users.credentialType.nt")}</option>
            </select>
          )}
        </Field>
        <Field label={t("users.groups")}>
          {(id) => (
            <select id={id} value={group} onChange={(event) => setGroup(event.target.value)}>
              <option value="">{t("common.none")}</option>
              {(groups.data ?? []).map((entry) => (
                <option key={entry.groupname} value={entry.groupname}>
                  {entry.groupname}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t("users.vlan")}>
          {(id) => <input id={id} value={vlan} onChange={(event) => setVlan(event.target.value)} />}
        </Field>
        <Field label={t("users.expires")}>
          {(id) => (
            <input
              id={id}
              type="datetime-local"
              value={expires}
              onChange={(event) => setExpires(event.target.value)}
            />
          )}
        </Field>
        <Field label={t("common.owner")}>
          {(id) => <input id={id} value={owner} onChange={(event) => setOwner(event.target.value)} />}
        </Field>
        <Field label={t("common.note")}>
          {(id) => (
            <textarea id={id} value={note} onChange={(event) => setNote(event.target.value)} />
          )}
        </Field>
        <WarningList warnings={create.data?.warnings} />
      </form>
    </Modal>
  );
}

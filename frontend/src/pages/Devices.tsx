import type { ColumnDef } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { buildQuery, download } from "@/api/client";
import { useCreateDevice, useDevices, useGroups, useMacFormats, useSettings } from "@/api/hooks";
import type { UserListItem } from "@/api/types";
import { DataTable } from "@/components/DataTable";
import { ErrorBox, Field, Modal, Pagination, Spinner, StatusBadge } from "@/components/ui";
import { useI18n } from "@/i18n";
import { formatDateTime, toIso } from "@/lib/format";

import { ImportDialog } from "./ImportDialog";

const LIMIT = 50;

export function DevicesPage() {
  const { t, language } = useI18n();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [location, setLocation] = useState("");
  const [deviceType, setDeviceType] = useState("");
  const [offset, setOffset] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);

  const formats = useMacFormats();
  const settings = useSettings();
  const showWarning = settings.data?.values.show_mab_warning !== false;
  // Ein Filterobjekt fuer Liste und Export – der Export muss genau die
  // angezeigte Menge liefern (FR-8).
  const filters = {
    search: search || undefined,
    location: location || undefined,
    device_type: deviceType || undefined,
  };
  const { data, isLoading, error } = useDevices({ ...filters, limit: LIMIT, offset });

  const columns = useMemo<ColumnDef<UserListItem, unknown>[]>(
    () => [
      { accessorKey: "username", header: () => t("devices.mac") },
      {
        accessorKey: "device_type",
        header: () => t("devices.type"),
        cell: ({ getValue }) => (getValue() as string | null) ?? "–",
      },
      {
        accessorKey: "location",
        header: () => t("common.location"),
        cell: ({ getValue }) => (getValue() as string | null) ?? "–",
      },
      {
        accessorKey: "inventory_no",
        header: () => t("devices.inventory"),
        cell: ({ getValue }) => (getValue() as string | null) ?? "–",
      },
      {
        accessorKey: "groups",
        header: () => t("users.groups"),
        cell: ({ row }) => row.original.groups.join(", ") || "–",
      },
      {
        accessorKey: "status",
        header: () => t("users.status"),
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        accessorKey: "expires_at",
        header: () => t("users.expires"),
        cell: ({ getValue }) => formatDateTime(getValue() as string | null, language),
      },
    ],
    [language, t],
  );

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>{t("devices.title")}</h1>
          <p className="muted">
            {t("devices.macFormat")}: <code>{formats.data?.active ?? "…"}</code>
          </p>
        </div>
        <div className="actions">
          <button type="button" onClick={() => setShowImport(true)}>
            {t("common.import")}
          </button>
          <button
            type="button"
            onClick={() =>
              void download(`/devices/export${buildQuery(filters)}`, "geraete.csv")
            }
          >
            {t("common.export")}
          </button>
          <button type="button" className="primary" onClick={() => setShowCreate(true)}>
            {t("devices.new")}
          </button>
        </div>
      </header>

      {showWarning ? <p className="alert alert-warning">{t("devices.warning")}</p> : null}

      <div className="filters">
        <input
          placeholder={t("common.search")}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
        <input
          placeholder={t("common.location")}
          value={location}
          onChange={(event) => setLocation(event.target.value)}
        />
        <input
          placeholder={t("devices.type")}
          value={deviceType}
          onChange={(event) => setDeviceType(event.target.value)}
        />
      </div>

      <ErrorBox error={error} />
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

      {showCreate ? <CreateDeviceDialog onClose={() => setShowCreate(false)} /> : null}
      {showImport ? <ImportDialog kind="device" onClose={() => setShowImport(false)} /> : null}
    </section>
  );
}

function CreateDeviceDialog({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const create = useCreateDevice();
  const groups = useGroups();

  const [mac, setMac] = useState("");
  const [deviceType, setDeviceType] = useState("");
  const [location, setLocation] = useState("");
  const [inventory, setInventory] = useState("");
  const [owner, setOwner] = useState("");
  const [vlan, setVlan] = useState("");
  const [group, setGroup] = useState("");
  const [expires, setExpires] = useState("");

  return (
    <Modal
      title={t("devices.new")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button
            type="submit"
            form="create-device"
            className="primary"
            disabled={create.isPending}
          >
            {t("common.create")}
          </button>
        </>
      }
    >
      <form
        id="create-device"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            {
              mac,
              use_mac_as_password: true,
              vlan: vlan || null,
              expires_at: toIso(expires),
              groups: group ? [{ groupname: group, priority: 1 }] : [],
              meta: {
                device_type: deviceType || null,
                location: location || null,
                inventory_no: inventory || null,
                owner: owner || null,
              },
            },
            { onSuccess: onClose },
          );
        }}
      >
        <ErrorBox error={create.error} />
        <p className="alert alert-warning">{t("devices.warning")}</p>
        <Field label={t("devices.mac")} required>
          {(id) => (
            <input
              id={id}
              value={mac}
              placeholder="aa:bb:cc:dd:ee:ff"
              onChange={(event) => setMac(event.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t("devices.type")}>
          {(id) => (
            <input
              id={id}
              value={deviceType}
              onChange={(event) => setDeviceType(event.target.value)}
            />
          )}
        </Field>
        <Field label={t("common.location")}>
          {(id) => (
            <input id={id} value={location} onChange={(event) => setLocation(event.target.value)} />
          )}
        </Field>
        <Field label={t("devices.inventory")}>
          {(id) => (
            <input
              id={id}
              value={inventory}
              onChange={(event) => setInventory(event.target.value)}
            />
          )}
        </Field>
        <Field label={t("common.owner")}>
          {(id) => (
            <input id={id} value={owner} onChange={(event) => setOwner(event.target.value)} />
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
      </form>
    </Modal>
  );
}

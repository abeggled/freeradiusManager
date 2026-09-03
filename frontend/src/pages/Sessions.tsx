import { useState } from "react";

import { useCoA, useSessionDetail, useSessions, useTerminateCauses } from "@/api/hooks";
import type { SessionItem } from "@/api/types";
import { ConfirmDialog, ErrorBox, Field, Modal, Spinner } from "@/components/ui";
import { usePermissions } from "@/hooks/usePermissions";
import { useI18n } from "@/i18n";
import { formatBytes, formatDateTime, formatDuration, toIso } from "@/lib/format";

const LIMIT = 50;

export function SessionsPage() {
  const { t, language } = useI18n();
  const { canWrite } = usePermissions();
  const [username, setUsername] = useState("");
  const [mac, setMac] = useState("");
  const [nas, setNas] = useState("");
  const [cause, setCause] = useState("");
  const [activeOnly, setActiveOnly] = useState(true);
  const [startFrom, setStartFrom] = useState("");
  const [startTo, setStartTo] = useState("");
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [page, setPage] = useState(0);
  const [detailId, setDetailId] = useState<number | null>(null);
  const [disconnecting, setDisconnecting] = useState<SessionItem | null>(null);
  const [coaTarget, setCoaTarget] = useState<SessionItem | null>(null);

  const causes = useTerminateCauses();
  const coa = useCoA();
  const { data, isLoading, error } = useSessions({
    username: username || undefined,
    calling_station_id: mac || undefined,
    nas_ip_address: nas || undefined,
    terminate_cause: cause || undefined,
    start_from: toIso(startFrom) ?? undefined,
    start_to: toIso(startTo) ?? undefined,
    active_only: activeOnly,
    limit: LIMIT,
    cursor: cursors[page] ?? undefined,
  });

  const resetPaging = () => {
    setCursors([null]);
    setPage(0);
  };

  return (
    <section>
      <header className="page-header">
        <h1>{t("sessions.title")}</h1>
      </header>

      <div className="filters">
        <input
          placeholder={t("users.username")}
          value={username}
          onChange={(event) => {
            setUsername(event.target.value);
            resetPaging();
          }}
        />
        <input
          placeholder={t("sessions.mac")}
          value={mac}
          onChange={(event) => {
            setMac(event.target.value);
            resetPaging();
          }}
        />
        <input
          placeholder={t("sessions.nasFilter")}
          value={nas}
          onChange={(event) => {
            setNas(event.target.value);
            resetPaging();
          }}
        />
        <select
          value={cause}
          onChange={(event) => {
            setCause(event.target.value);
            resetPaging();
          }}
        >
          <option value="">{t("sessions.terminateCause")}: {t("common.all")}</option>
          {(causes.data ?? []).map((entry) => (
            <option key={entry} value={entry}>
              {entry}
            </option>
          ))}
        </select>
        <label className="range">
          <span>{t("sessions.from")}</span>
          <input
            type="datetime-local"
            value={startFrom}
            onChange={(event) => {
              setStartFrom(event.target.value);
              resetPaging();
            }}
          />
        </label>
        <label className="range">
          <span>{t("sessions.to")}</span>
          <input
            type="datetime-local"
            value={startTo}
            onChange={(event) => {
              setStartTo(event.target.value);
              resetPaging();
            }}
          />
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(event) => {
              setActiveOnly(event.target.checked);
              resetPaging();
            }}
          />
          {t("sessions.active")}
        </label>
        <button
          type="button"
          onClick={() => {
            setUsername("");
            setMac("");
            setNas("");
            setCause("");
            setStartFrom("");
            setStartTo("");
            resetPaging();
          }}
        >
          {t("common.reset")}
        </button>
      </div>

      <ErrorBox error={error ?? coa.error} />
      {coa.data ? (
        <p className={coa.data.ok ? "alert alert-info" : "alert alert-warning"}>
          {coa.data.action} → {coa.data.nas}: {coa.data.message}
        </p>
      ) : null}

      {isLoading ? (
        <Spinner />
      ) : (
        <>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t("users.username")}</th>
                  <th>{t("sessions.mac")}</th>
                  <th>{t("sessions.nas")}</th>
                  <th>{t("sessions.ssid")}</th>
                  <th>{t("sessions.framedIp")}</th>
                  <th>{t("sessions.start")}</th>
                  <th>{t("sessions.duration")}</th>
                  <th>{t("sessions.volume")}</th>
                  <th>{t("sessions.terminateCause")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((session) => (
                  <tr
                    key={session.radacctid}
                    className="clickable"
                    onClick={() => setDetailId(session.radacctid)}
                  >
                    <td>{session.username}</td>
                    <td>{session.callingstationid}</td>
                    <td>{session.nas_shortname ?? session.nasipaddress}</td>
                    <td>{session.ssid ?? "–"}</td>
                    <td>{session.framedipaddress || "–"}</td>
                    <td>{formatDateTime(session.acctstarttime, language)}</td>
                    <td>
                      {session.active
                        ? t("sessions.running")
                        : formatDuration(session.acctsessiontime)}
                    </td>
                    <td>
                      {formatBytes(
                        (session.acctinputoctets ?? 0) + (session.acctoutputoctets ?? 0),
                      )}
                    </td>
                    <td>{session.acctterminatecause || "–"}</td>
                    <td className="row-actions" onClick={(event) => event.stopPropagation()}>
                      {session.active && canWrite ? (
                        <>
                          <button type="button" onClick={() => setDisconnecting(session)}>
                            {t("sessions.disconnect")}
                          </button>
                          <button type="button" onClick={() => setCoaTarget(session)}>
                            {t("sessions.coa")}
                          </button>
                        </>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>
              {t("common.previous")}
            </button>
            <span>
              {t("sessions.approximate", { count: data?.meta.approximate_total ?? 0 })}
            </span>
            <button
              type="button"
              disabled={!data?.meta.next_cursor}
              onClick={() => {
                setCursors((current) => {
                  const next = [...current];
                  next[page + 1] = data?.meta.next_cursor ?? null;
                  return next;
                });
                setPage(page + 1);
              }}
            >
              {t("common.next")}
            </button>
          </div>
        </>
      )}

      {detailId !== null ? (
        <SessionDetailDialog radacctid={detailId} onClose={() => setDetailId(null)} />
      ) : null}

      {disconnecting ? (
        <ConfirmDialog
          title={t("sessions.disconnect")}
          message={t("sessions.disconnectConfirm", { name: disconnecting.username })}
          onConfirm={() =>
            coa.mutate(
              { action: "disconnect", acctuniqueid: disconnecting.acctuniqueid },
              { onSuccess: () => setDisconnecting(null) },
            )
          }
          onCancel={() => setDisconnecting(null)}
          busy={coa.isPending}
        />
      ) : null}

      {coaTarget ? (
        <CoaDialog session={coaTarget} onClose={() => setCoaTarget(null)} />
      ) : null}
    </section>
  );
}

/** Detailansicht einer Session (FR-5): Zeiten, Volumen, NAS-Port und SSID. */
function SessionDetailDialog({
  radacctid,
  onClose,
}: {
  radacctid: number;
  onClose: () => void;
}) {
  const { t, language } = useI18n();
  const { data, isLoading, error } = useSessionDetail(radacctid);

  return (
    <Modal
      title={t("sessions.title")}
      onClose={onClose}
      footer={
        <button type="button" onClick={onClose}>
          {t("common.close")}
        </button>
      }
    >
      <ErrorBox error={error} />
      {isLoading ? <Spinner /> : null}
      {data ? (
        <dl>
          <dt>{t("users.username")}</dt>
          <dd>{data.username}</dd>
          <dt>{t("sessions.mac")}</dt>
          <dd>{data.callingstationid || "–"}</dd>
          <dt>{t("sessions.ssid")}</dt>
          <dd>{data.ssid ?? "–"}</dd>
          <dt>{t("sessions.nas")}</dt>
          <dd>{data.nas_shortname ?? data.nasipaddress}</dd>
          <dt>{t("sessions.port")}</dt>
          <dd>{data.nasportid ?? "–"}</dd>
          <dt>{t("sessions.framedIp")}</dt>
          <dd>{data.framedipaddress || "–"}</dd>
          <dt>{t("sessions.start")}</dt>
          <dd>{formatDateTime(data.acctstarttime, language)}</dd>
          <dt>{t("sessions.stop")}</dt>
          <dd>
            {data.active ? t("sessions.running") : formatDateTime(data.acctstoptime, language)}
          </dd>
          <dt>{t("sessions.duration")}</dt>
          <dd>
            {data.active ? t("sessions.running") : formatDuration(data.acctsessiontime)}
          </dd>
          <dt>{t("sessions.volume")}</dt>
          <dd>
            {formatBytes(data.acctinputoctets ?? 0)} ↓ / {formatBytes(data.acctoutputoctets ?? 0)} ↑
          </dd>
          <dt>{t("sessions.terminateCause")}</dt>
          <dd>{data.acctterminatecause || "–"}</dd>
          <dt>Acct-Session-Id</dt>
          <dd>
            <code>{data.acctsessionid}</code>
          </dd>
        </dl>
      ) : null}
    </Modal>
  );
}

function CoaDialog({ session, onClose }: { session: SessionItem; onClose: () => void }) {
  const { t } = useI18n();
  const coa = useCoA();
  const [vlan, setVlan] = useState("");

  return (
    <Modal
      title={t("sessions.coa")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button
            type="button"
            className="primary"
            disabled={!vlan || coa.isPending}
            onClick={() =>
              coa.mutate(
                { action: "coa", acctuniqueid: session.acctuniqueid, vlan },
                { onSuccess: onClose },
              )
            }
          >
            {t("common.confirm")}
          </button>
        </>
      }
    >
      <ErrorBox error={coa.error} />
      <p>{t("sessions.coaConfirm")}</p>
      <Field label={t("sessions.newVlan")} required>
        {(id) => <input id={id} value={vlan} onChange={(event) => setVlan(event.target.value)} />}
      </Field>
    </Modal>
  );
}

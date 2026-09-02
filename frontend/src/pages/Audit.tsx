import { useState } from "react";

import { useAudit } from "@/api/hooks";
import { ErrorBox, Pagination, Spinner } from "@/components/ui";
import { useI18n } from "@/i18n";
import { formatDateTime } from "@/lib/format";

const LIMIT = 50;

export function AuditPage() {
  const { t, language } = useI18n();
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [objectId, setObjectId] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);

  const { data, isLoading, error } = useAudit({
    actor: actor || undefined,
    action: action || undefined,
    object_id: objectId || undefined,
    limit: LIMIT,
    offset,
  });

  return (
    <section>
      <header className="page-header">
        <h1>{t("audit.title")}</h1>
      </header>
      <p className="alert alert-info">{t("audit.immutable")}</p>

      <div className="filters">
        <input
          placeholder={t("audit.actor")}
          value={actor}
          onChange={(event) => {
            setActor(event.target.value);
            setOffset(0);
          }}
        />
        <input
          placeholder={t("audit.action")}
          value={action}
          onChange={(event) => {
            setAction(event.target.value);
            setOffset(0);
          }}
        />
        <input
          placeholder={t("audit.object")}
          value={objectId}
          onChange={(event) => {
            setObjectId(event.target.value);
            setOffset(0);
          }}
        />
      </div>

      <ErrorBox error={error} />
      {isLoading ? (
        <Spinner />
      ) : (
        <>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t("authlog.date")}</th>
                  <th>{t("audit.actor")}</th>
                  <th>{t("audit.action")}</th>
                  <th>{t("audit.object")}</th>
                  <th>{t("audit.result")}</th>
                  <th>{t("common.details")}</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((entry) => (
                  <tr key={entry.id}>
                    <td>{formatDateTime(entry.ts, language)}</td>
                    <td>
                      {entry.actor_name}
                      {entry.actor_ip ? <small> ({entry.actor_ip})</small> : null}
                    </td>
                    <td>
                      <code>{entry.action}</code>
                    </td>
                    <td>
                      {entry.object_type}
                      {entry.object_id ? `: ${entry.object_id}` : ""}
                    </td>
                    <td>
                      <span
                        className={`badge badge-${entry.result === "success" ? "active" : "disabled"}`}
                      >
                        {entry.result}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="link"
                        onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                      >
                        {t("common.showMore")}
                      </button>
                      {expanded === entry.id ? (
                        <div className="audit-details">
                          {entry.message ? <p>{entry.message}</p> : null}
                          {entry.before ? (
                            <>
                              <strong>{t("audit.before")}</strong>
                              <pre>{JSON.stringify(entry.before, null, 2)}</pre>
                            </>
                          ) : null}
                          {entry.after ? (
                            <>
                              <strong>{t("audit.after")}</strong>
                              <pre>{JSON.stringify(entry.after, null, 2)}</pre>
                            </>
                          ) : null}
                        </div>
                      ) : null}
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
    </section>
  );
}

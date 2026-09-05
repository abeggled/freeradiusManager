import { useState } from "react";
import { useSearchParams } from "react-router-dom";

import { useDiagnosis } from "@/api/hooks";
import { ErrorBox, Field, Spinner } from "@/components/ui";
import { useI18n } from "@/i18n";
import { formatBytes, formatDateTime, formatDuration, toOctets } from "@/lib/format";

/** Diagnose-Ansicht: Klartext-Hinweise statt `radiusd -X` (Spezifikation FR-6). */
export function DiagnosePage() {
  const { t, language } = useI18n();
  const [params, setParams] = useSearchParams();
  const subject = params.get("subject") ?? "";
  const [input, setInput] = useState(subject);

  const { data, isLoading, error } = useDiagnosis(subject);

  return (
    <section>
      <header className="page-header">
        <h1>{t("diagnose.title")}</h1>
      </header>

      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault();
          setParams(input ? { subject: input } : {});
        }}
      >
        <Field label={t("diagnose.subject")}>
          {(id) => (
            <input
              id={id}
              value={input}
              placeholder="anna / aa:bb:cc:dd:ee:ff"
              onChange={(event) => setInput(event.target.value)}
            />
          )}
        </Field>
        <button type="submit" className="primary">
          {t("diagnose.run")}
        </button>
      </form>

      <ErrorBox error={error} />
      {!subject ? <p className="muted">{t("diagnose.noResult")}</p> : null}
      {isLoading && subject ? <Spinner /> : null}

      {data ? (
        <>
          <div className="card">
            <h2>{t("diagnose.hints")}</h2>
            <ul className="hints">
              {data.hints.map((hint) => (
                <li key={hint.code} className={`alert alert-${hint.severity}`}>
                  {hint.message}
                </li>
              ))}
            </ul>
            <dl>
              <dt>{t("common.displayName")}</dt>
              <dd>{data.subject_name ?? "–"}</dd>
              <dt>{t("users.status")}</dt>
              <dd>{data.status}</dd>
              <dt>{t("users.groups")}</dt>
              <dd>{data.groups.join(", ") || "–"}</dd>
              <dt>{t("users.vlan")}</dt>
              <dd>{data.vlan ?? "–"}</dd>
            </dl>
          </div>

          <div className="card">
            <h2>{t("diagnose.attempts")}</h2>
            {data.attempts.length === 0 ? (
              <p className="muted">{t("common.empty")}</p>
            ) : (
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>{t("authlog.date")}</th>
                      <th>{t("authlog.reply")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.attempts.map((attempt) => (
                      <tr key={attempt.id}>
                        <td>{formatDateTime(attempt.authdate, language)}</td>
                        <td>
                          <span
                            className={`badge badge-${attempt.accepted ? "active" : "disabled"}`}
                          >
                            {attempt.reply}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {data.last_session ? (
            <div className="card">
              <h2>{t("diagnose.lastSession")}</h2>
              <dl>
                <dt>{t("sessions.nas")}</dt>
                <dd>{data.last_session.nas_shortname ?? data.last_session.nasipaddress}</dd>
                <dt>{t("sessions.mac")}</dt>
                <dd>{data.last_session.callingstationid}</dd>
                <dt>{t("sessions.ssid")}</dt>
                <dd>{data.last_session.ssid ?? "–"}</dd>
                <dt>{t("sessions.start")}</dt>
                <dd>{formatDateTime(data.last_session.acctstarttime, language)}</dd>
                <dt>{t("sessions.duration")}</dt>
                <dd>
                  {data.last_session.active
                    ? t("sessions.running")
                    : formatDuration(data.last_session.acctsessiontime)}
                </dd>
                <dt>{t("sessions.volume")}</dt>
                <dd>
                  {formatBytes(
                    toOctets(data.last_session.acctinputoctets) +
                      toOctets(data.last_session.acctoutputoctets),
                  )}
                </dd>
              </dl>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";

import { useAuthLog } from "@/api/hooks";
import { ErrorBox, Spinner } from "@/components/ui";
import { useI18n } from "@/i18n";
import { formatDateTime } from "@/lib/format";

const LIMIT = 50;

export function AuthLogPage() {
  const { t, language } = useI18n();
  const [username, setUsername] = useState("");
  const [onlyRejects, setOnlyRejects] = useState(false);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [page, setPage] = useState(0);

  const { data, isLoading, error } = useAuthLog({
    username: username || undefined,
    only_rejects: onlyRejects,
    limit: LIMIT,
    cursor: cursors[page] ?? undefined,
  });

  return (
    <section>
      <header className="page-header">
        <h1>{t("authlog.title")}</h1>
        <Link className="button" to="/diagnose">
          {t("diagnose.title")}
        </Link>
      </header>

      <div className="filters">
        <input
          placeholder={t("users.username")}
          value={username}
          onChange={(event) => {
            setUsername(event.target.value);
            setCursors([null]);
            setPage(0);
          }}
        />
        <label className="checkbox">
          <input
            type="checkbox"
            checked={onlyRejects}
            onChange={(event) => {
              setOnlyRejects(event.target.checked);
              setCursors([null]);
              setPage(0);
            }}
          />
          {t("authlog.onlyRejects")}
        </label>
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
                  <th>{t("users.username")}</th>
                  <th>{t("authlog.reply")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((entry) => (
                  <tr key={entry.id}>
                    <td>{formatDateTime(entry.authdate, language)}</td>
                    <td>{entry.username}</td>
                    <td>
                      <span className={`badge badge-${entry.accepted ? "active" : "disabled"}`}>
                        {entry.reply}
                      </span>
                    </td>
                    <td>
                      <Link
                        className="link"
                        to={`/diagnose?subject=${encodeURIComponent(entry.username)}`}
                      >
                        {t("diagnose.title")}
                      </Link>
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
    </section>
  );
}

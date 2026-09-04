import { useStats } from "@/api/hooks";
import { ErrorBox, Spinner } from "@/components/ui";
import { useI18n } from "@/i18n";
import { formatBytes, formatDateTime, toOctets } from "@/lib/format";

function Tile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="tile">
      <span className="tile-value">{value}</span>
      <span className="tile-label">{label}</span>
    </div>
  );
}

export function DashboardPage() {
  const { t, language } = useI18n();
  const { data, isLoading, error } = useStats();

  if (isLoading) return <Spinner />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  return (
    <section>
      <h1>{t("dashboard.title")}</h1>
      {data.stale ? <p className="alert alert-warning">{t("dashboard.stale")}</p> : null}
      <p className="muted">
        {t("dashboard.computedAt")}: {formatDateTime(data.computed_at, language)}
      </p>

      <div className="tiles">
        <Tile label={t("dashboard.activeSessions")} value={data.active_sessions} />
        <Tile label={t("dashboard.sessionsStarted")} value={data.sessions_started} />
        <Tile label={t("dashboard.accepts")} value={data.accepts} />
        <Tile label={t("dashboard.rejects")} value={data.rejects} />
        <Tile
          label={t("dashboard.traffic")}
          value={formatBytes(toOctets(data.input_octets) + toOctets(data.output_octets))}
        />
        <Tile label={t("dashboard.users")} value={data.users_total} />
        <Tile label={t("dashboard.devices")} value={data.devices_total} />
        <Tile label={t("dashboard.groups")} value={data.groups_total} />
        <Tile label={t("dashboard.nas")} value={data.nas_total} />
      </div>

      <div className="columns">
        <div>
          <h2>{t("dashboard.topUsers")}</h2>
          <ul className="ranking">
            {data.top_users.map((entry) => (
              <li key={entry.username}>
                <span>{entry.username}</span>
                <span>
                  {entry.sessions} {t("dashboard.sessions")}
                </span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h2>{t("dashboard.topNas")}</h2>
          <ul className="ranking">
            {data.top_nas.map((entry) => (
              <li key={entry.nasipaddress}>
                <span>{entry.nasipaddress}</span>
                <span>
                  {entry.sessions} {t("dashboard.sessions")}
                </span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h2>{t("dashboard.topRejected")}</h2>
          <ul className="ranking">
            {data.top_rejected.map((entry) => (
              <li key={entry.username}>
                <span>{entry.username}</span>
                <span>
                  {entry.attempts} {t("dashboard.attempts")}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

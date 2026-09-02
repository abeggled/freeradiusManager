import { useState } from "react";

import { useSettings, useUpdateSettings } from "@/api/hooks";
import { ErrorBox, Field, Spinner } from "@/components/ui";
import { useI18n, type TranslationKey } from "@/i18n";

export function SettingsPage() {
  const { t } = useI18n();
  const { data, isLoading, error } = useSettings();
  const update = useUpdateSettings();
  const [draft, setDraft] = useState<Record<string, unknown>>({});

  if (isLoading) return <Spinner />;
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;

  const value = <T,>(key: string, fallback: T): T =>
    (draft[key] as T) ?? (data.values[key] as T) ?? fallback;

  return (
    <section>
      <header className="page-header">
        <h1>{t("settings.title")}</h1>
      </header>
      <ErrorBox error={update.error} />
      {update.isSuccess ? <p className="alert alert-info">{t("settings.saved")}</p> : null}

      <form
        className="card"
        onSubmit={(event) => {
          event.preventDefault();
          update.mutate(draft);
        }}
      >
        <Field label={t("settings.macFormat")} hint={t("settings.macFormatHint")}>
          {(id) => (
            <select
              id={id}
              value={value("mac_format", "colon_lower")}
              onChange={(event) => setDraft({ ...draft, mac_format: event.target.value })}
            >
              {data.options.mac_format.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.key} — {option.example}
                </option>
              ))}
            </select>
          )}
        </Field>

        <Field label={t("settings.defaultCredential")} hint={t("users.credentialTypeHint")}>
          {(id) => (
            <select
              id={id}
              value={value("default_credential_type", "both")}
              onChange={(event) =>
                setDraft({ ...draft, default_credential_type: event.target.value })
              }
            >
              {data.options.credential_type.map((option) => (
                <option key={option} value={option}>
                  {t(`users.credentialType.${option}` as TranslationKey)}
                </option>
              ))}
            </select>
          )}
        </Field>

        <Field label={t("settings.auditRetention")}>
          {(id) => (
            <input
              id={id}
              type="number"
              min={1}
              value={value("audit_retention_days", 730)}
              onChange={(event) =>
                setDraft({ ...draft, audit_retention_days: Number(event.target.value) })
              }
            />
          )}
        </Field>

        <Field label={t("settings.accountingRetention")}>
          {(id) => (
            <input
              id={id}
              type="number"
              min={1}
              value={value("accounting_retention_days", 365)}
              onChange={(event) =>
                setDraft({ ...draft, accounting_retention_days: Number(event.target.value) })
              }
            />
          )}
        </Field>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={value("show_mab_warning", true)}
            onChange={(event) => setDraft({ ...draft, show_mab_warning: event.target.checked })}
          />
          {t("settings.mabWarning")}
        </label>

        <button type="submit" className="primary" disabled={update.isPending}>
          {t("common.save")}
        </button>
      </form>
    </section>
  );
}

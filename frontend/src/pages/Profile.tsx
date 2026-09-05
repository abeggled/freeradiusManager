import { useState } from "react";

import {
  useChangeOwnPassword,
  useMe,
  useOwnTotpConfirm,
  useOwnTotpEnroll,
} from "@/api/hooks";
import { endSession } from "@/api/client";
import { Copyable, ErrorBox, Field, Spinner, TotpCodeInput } from "@/components/ui";
import { useI18n, type Language, type TranslationKey } from "@/i18n";

export function ProfilePage() {
  const { t, language, setLanguage } = useI18n();
  const me = useMe();
  const changePassword = useChangeOwnPassword();
  const enroll = useOwnTotpEnroll();
  const confirm = useOwnTotpConfirm();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [totpPassword, setTotpPassword] = useState("");
  const [code, setCode] = useState("");

  if (me.isLoading) return <Spinner />;
  if (!me.data) return <ErrorBox error={me.error} />;

  return (
    <section>
      <header className="page-header">
        <h1>{t("profile.title")}</h1>
      </header>

      <div className="columns">
        <div className="card">
          <h2>{me.data.username}</h2>
          <dl>
            <dt>{t("accounts.role")}</dt>
            <dd>{t(`accounts.role.${me.data.role}` as TranslationKey)}</dd>
            <dt>{t("accounts.email")}</dt>
            <dd>{me.data.email ?? "–"}</dd>
            <dt>{t("accounts.totp")}</dt>
            <dd>{me.data.totp_enabled ? t("profile.totpActive") : t("common.no")}</dd>
          </dl>
          <Field label={t("common.language")}>
            {(id) => (
              <select
                id={id}
                value={language}
                onChange={(event) => setLanguage(event.target.value as Language)}
              >
                <option value="de">Deutsch</option>
                <option value="en">English</option>
              </select>
            )}
          </Field>
        </div>

        <div className="card">
          <h2>{t("profile.changePassword")}</h2>
          <ErrorBox error={changePassword.error} />
          <form
            onSubmit={(event) => {
              event.preventDefault();
              changePassword.mutate(
                { current_password: current, new_password: next },
                {
                  onSuccess: () => {
                    setCurrent("");
                    setNext("");
                    // Der Wechsel setzt `password_changed_at` und entwertet das
                    // eigene Cookie. Ohne diesen Schritt bliebe die Oberfläche
                    // sichtbar, aber unbenutzbar.
                    endSession();
                  },
                },
              );
            }}
          >
            <Field label={t("profile.currentPassword")} required>
              {(id) => (
                <input
                  id={id}
                  name="current-password"
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(event) => setCurrent(event.target.value)}
                  required
                />
              )}
            </Field>
            <Field label={t("profile.newPassword")} required>
              {(id) => (
                <input
                  id={id}
                  name="new-password"
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={next}
                  onChange={(event) => setNext(event.target.value)}
                  required
                />
              )}
            </Field>
            <button type="submit" className="primary" disabled={changePassword.isPending}>
              {t("common.save")}
            </button>
          </form>
        </div>

        <div className="card">
          <h2>{t("profile.setupTotp")}</h2>
          <ErrorBox error={enroll.error ?? confirm.error} />
          {enroll.data ? (
            <>
              <p>
                <strong>{t("login.totpSecret")}:</strong> <Copyable value={enroll.data.secret} />
              </p>
              <p className="hint">{enroll.data.provisioning_uri}</p>
              <Field label={t("login.totpCode")} required>
                {(id) => <TotpCodeInput id={id} value={code} onChange={setCode} />}
              </Field>
              <button
                type="button"
                className="primary"
                onClick={() => confirm.mutate({ code })}
                disabled={confirm.isPending}
              >
                {t("common.confirm")}
              </button>
            </>
          ) : me.data.totp_enabled ? (
            // Ein aktiver Faktor lässt sich nicht selbst ersetzen; das Backend
            // weist die Einrichtung ab. Die Schaltfläche wäre also dauerhaft
            // funktionslos – stattdessen wird der Zustand benannt.
            <p className="hint">{t("profile.totpAlreadyActive")}</p>
          ) : (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                enroll.mutate(
                  { current_password: totpPassword },
                  { onSuccess: () => setTotpPassword("") },
                );
              }}
            >
              <p className="hint">{t("profile.totpPasswordHint")}</p>
              <Field label={t("profile.currentPassword")} required>
                {(id) => (
                  <input
                    id={id}
                    name="current-password"
                    type="password"
                    autoComplete="current-password"
                    value={totpPassword}
                    onChange={(event) => setTotpPassword(event.target.value)}
                    required
                  />
                )}
              </Field>
              <button type="submit" disabled={enroll.isPending || !totpPassword}>
                {t("profile.setupTotp")}
              </button>
            </form>
          )}
        </div>
      </div>
    </section>
  );
}

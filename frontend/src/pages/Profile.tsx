import { useState } from "react";

import {
  useChangeOwnPassword,
  useMe,
  useOwnTotpConfirm,
  useOwnTotpEnroll,
} from "@/api/hooks";
import { Copyable, ErrorBox, Field, Spinner } from "@/components/ui";
import { useI18n, type Language, type TranslationKey } from "@/i18n";

export function ProfilePage() {
  const { t, language, setLanguage } = useI18n();
  const me = useMe();
  const changePassword = useChangeOwnPassword();
  const enroll = useOwnTotpEnroll();
  const confirm = useOwnTotpConfirm();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
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
                  },
                },
              );
            }}
          >
            <Field label={t("profile.currentPassword")} required>
              {(id) => (
                <input
                  id={id}
                  type="password"
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
                  type="password"
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
                {(id) => (
                  <input id={id} value={code} onChange={(event) => setCode(event.target.value)} />
                )}
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
          ) : (
            <button type="button" onClick={() => enroll.mutate()} disabled={enroll.isPending}>
              {t("profile.setupTotp")}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}

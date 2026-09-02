import { useState } from "react";

import { useLogin, useLoginTotp, useOidcStatus, useTotpConfirm, useTotpEnroll } from "@/api/hooks";
import { ErrorBox, Field } from "@/components/ui";
import { useI18n } from "@/i18n";

type Stage = "credentials" | "totp" | "totp-setup";

export function LoginPage({ onAuthenticated }: { onAuthenticated: () => void }) {
  const { t } = useI18n();
  const [stage, setStage] = useState<Stage>("credentials");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState("");
  const [secret, setSecret] = useState("");
  const [uri, setUri] = useState("");

  const login = useLogin();
  const loginTotp = useLoginTotp();
  const enroll = useTotpEnroll();
  const confirm = useTotpConfirm();
  const oidc = useOidcStatus();

  const error = login.error ?? loginTotp.error ?? enroll.error ?? confirm.error;

  const submitCredentials = (event: React.FormEvent) => {
    event.preventDefault();
    login.mutate(
      { username, password },
      {
        onSuccess: (response) => {
          if (response.status === "authenticated") {
            onAuthenticated();
            return;
          }
          setChallenge(response.challenge ?? "");
          if (response.status === "totp_required") {
            setStage("totp");
            return;
          }
          enroll.mutate(response.challenge ?? "", {
            onSuccess: (setup) => {
              setSecret(setup.secret);
              setUri(setup.provisioning_uri);
              setStage("totp-setup");
            },
          });
        },
      },
    );
  };

  const submitTotp = (event: React.FormEvent) => {
    event.preventDefault();
    const mutation = stage === "totp" ? loginTotp : confirm;
    mutation.mutate(
      { challenge, totp_code: code },
      { onSuccess: () => onAuthenticated() },
    );
  };

  return (
    <div className="login">
      <div className="login-card">
        <h1>{t("app.title")}</h1>
        <p className="muted">{t("app.subtitle")}</p>
        <ErrorBox error={error} />

        {stage === "credentials" ? (
          <form onSubmit={submitCredentials}>
            <h2>{t("login.title")}</h2>
            <Field label={t("login.username")} required>
              {(id) => (
                <input
                  id={id}
                  autoComplete="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  required
                />
              )}
            </Field>
            <Field label={t("login.password")} required>
              {(id) => (
                <input
                  id={id}
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />
              )}
            </Field>
            <button type="submit" className="primary" disabled={login.isPending}>
              {t("login.submit")}
            </button>
            {oidc.data?.enabled ? (
              <a className="oidc" href="/api/v1/auth/oidc/login">
                {t("login.oidc")}
              </a>
            ) : null}
          </form>
        ) : (
          <form onSubmit={submitTotp}>
            <h2>{stage === "totp" ? t("login.totpTitle") : t("login.totpSetupTitle")}</h2>
            <p className="muted">
              {stage === "totp" ? t("login.totpHint") : t("login.totpSetupHint")}
            </p>
            {stage === "totp-setup" ? (
              <div className="totp-setup">
                <p>
                  <strong>{t("login.totpSecret")}:</strong> <code>{secret}</code>
                </p>
                <p className="hint">{uri}</p>
              </div>
            ) : null}
            <Field label={t("login.totpCode")} required>
              {(id) => (
                <input
                  id={id}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  required
                />
              )}
            </Field>
            <button
              type="submit"
              className="primary"
              disabled={loginTotp.isPending || confirm.isPending}
            >
              {t("login.submit")}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

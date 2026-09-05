import type { ReactNode } from "react";
import { useEffect, useId, useState } from "react";

import { useI18n, type TranslationKey } from "@/i18n";
import { ApiError } from "@/api/client";
import type { ApiWarning, UserStatus } from "@/api/types";

export function Spinner({ label }: { label?: string }) {
  const { t } = useI18n();
  return (
    <p className="muted" role="status">
      {label ?? t("common.loading")}
    </p>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const { t } = useI18n();
  if (!error) return null;
  const message =
    error instanceof ApiError
      ? error.message
      : error instanceof Error
        ? error.message
        : String(error);
  const details =
    error instanceof ApiError && Object.keys(error.details).length > 0
      ? JSON.stringify(error.details)
      : null;
  return (
    <div className="alert alert-error" role="alert">
      <strong>{t("common.error")}:</strong> {message}
      {details ? <pre>{details}</pre> : null}
    </div>
  );
}

export function WarningList({ warnings }: { warnings: ApiWarning[] | undefined }) {
  if (!warnings || warnings.length === 0) return null;
  const unique = new Map(warnings.map((w) => [w.code + (w.attribute ?? ""), w]));
  return (
    <ul className="warnings">
      {[...unique.values()].map((warning) => (
        <li key={warning.code + (warning.attribute ?? "")} className="alert alert-warning">
          {warning.message}
        </li>
      ))}
    </ul>
  );
}

const STATUS_LABEL: Record<UserStatus, TranslationKey> = {
  active: "status.active",
  disabled: "status.disabled",
  expired: "status.expired",
  no_credentials: "status.no_credentials",
};

export function StatusBadge({ status }: { status: UserStatus }) {
  const { t } = useI18n();
  return <span className={`badge badge-${status}`}>{t(STATUS_LABEL[status])}</span>;
}

export function Field({
  label,
  hint,
  children,
  required,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>
        {label}
        {required ? <span aria-hidden="true"> *</span> : null}
      </label>
      {children(id)}
      {hint ? <p className="hint">{hint}</p> : null}
    </div>
  );
}

/** Wie ``TotpLoginRequest.totp_code`` im Backend. */
export const MAX_TOTP_CODE_LENGTH = 10;

export function TotpCodeInput({
  id,
  value,
  onChange,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
}) {
  // Gemeinsame Auszeichnung aller Einmalcode-Felder. Passwortmanager erkennen
  // das Feld an "one-time-code"; Bitwarden zieht zusaetzlich den Namen heran -
  // die von ``useId`` erzeugte Kennung sagt ihm nichts. Ohne beides muesste der
  // Code von Hand uebertragen werden.
  return (
    <input
      id={id}
      name="totp"
      type="text"
      inputMode="numeric"
      autoComplete="one-time-code"
      autoCorrect="off"
      autoCapitalize="off"
      spellCheck={false}
      maxLength={MAX_TOTP_CODE_LENGTH}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      required
    />
  );
}

export function Modal({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <header>
          <h2>{title}</h2>
          <button type="button" className="icon" onClick={onClose} aria-label="×">
            ×
          </button>
        </header>
        <div className="modal-body">{children}</div>
        {footer ? <footer>{footer}</footer> : null}
      </div>
    </div>
  );
}

/**
 * Bestaetigung destruktiver Aktionen inkl. Angabe der betroffenen Objektzahl
 * (Spezifikation NFR-4).
 */
export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  onConfirm,
  onCancel,
  busy,
}: {
  title: string;
  message: string;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
  busy?: boolean;
}) {
  const { t } = useI18n();
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button type="button" onClick={onCancel}>
            {t("common.cancel")}
          </button>
          <button type="button" className="danger" onClick={onConfirm} disabled={busy}>
            {confirmLabel ?? t("common.confirm")}
          </button>
        </>
      }
    >
      <p>{message}</p>
    </Modal>
  );
}

export function Pagination({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const { t } = useI18n();
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className="pagination">
      <button type="button" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        {t("common.previous")}
      </button>
      <span>
        {from}–{to} {t("common.of")} {total}
      </span>
      <button type="button" disabled={to >= total} onClick={() => onChange(offset + limit)}>
        {t("common.next")}
      </button>
    </div>
  );
}

export function Copyable({ value }: { value: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  return (
    <span className="copyable">
      <code>{value}</code>
      <button
        type="button"
        className="link"
        onClick={() => {
          void navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? t("common.copied") : t("common.copy")}
      </button>
    </span>
  );
}

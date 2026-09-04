import { useState } from "react";

import { download } from "@/api/client";
import { useImportCsv } from "@/api/hooks";
import { ErrorBox, Field, Modal } from "@/components/ui";
import { useI18n, type TranslationKey } from "@/i18n";

/** CSV-Import mit Vorschau und Dry-Run (Spezifikation FR-8). */
export function ImportDialog({
  kind,
  onClose,
}: {
  kind: "user" | "device";
  onClose: () => void;
}) {
  const { t } = useI18n();
  const [file, setFile] = useState<File | null>(null);
  const importCsv = useImportCsv();
  const report = importCsv.data;

  return (
    <Modal
      title={t("import.title")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.close")}
          </button>
          <button
            type="button"
            disabled={!file || importCsv.isPending}
            onClick={() => file && importCsv.mutate({ kind, file, dryRun: true })}
          >
            {t("import.preview")}
          </button>
          <button
            type="button"
            className="primary"
            disabled={!file || !report || !report.dry_run || importCsv.isPending}
            onClick={() => file && importCsv.mutate({ kind, file, dryRun: false })}
          >
            {t("import.apply")}
          </button>
        </>
      }
    >
      <ErrorBox error={importCsv.error} />
      <button
        type="button"
        className="link"
        onClick={() => void download(`/imports/template/${kind}`, `vorlage-${kind}.csv`)}
      >
        {t("import.template")}
      </button>
      <Field label={t("import.file")} required>
        {(id) => (
          <input
            id={id}
            type="file"
            accept=".csv,text/csv"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              // Die Vorschau gehört zur vorherigen Datei; sonst liesse sich eine
              // neue Datei anwenden, ohne sie je gesehen zu haben.
              importCsv.reset();
            }}
          />
        )}
      </Field>

      {report ? (
        <>
          <p className={report.errors > 0 ? "alert alert-warning" : "alert alert-info"}>
            {t("import.summary", {
              total: report.total,
              create: report.to_create,
              update: report.to_update,
              errors: report.errors,
            })}
          </p>
          {report.rows_truncated ? (
            <p className="hint">{t("import.truncated")}</p>
          ) : null}
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t("import.line")}</th>
                  <th>{t("import.action")}</th>
                  <th>{t("users.username")}</th>
                  <th>{t("common.details")}</th>
                </tr>
              </thead>
              <tbody>
                {report.rows.map((row) => (
                  <tr key={row.line} className={row.action === "error" ? "row-error" : undefined}>
                    <td>{row.line}</td>
                    <td>{t(`import.action.${row.action}` as TranslationKey)}</td>
                    <td>{row.username}</td>
                    <td>{row.message ?? JSON.stringify(row.values)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </Modal>
  );
}

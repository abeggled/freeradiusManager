import { useState } from "react";

import {
  useCreateNas,
  useDeleteNas,
  useNasList,
  useRevealSecret,
  useUpdateNas,
} from "@/api/hooks";
import type { NasItem } from "@/api/types";
import { ConfirmDialog, Copyable, ErrorBox, Field, Modal, Pagination, Spinner } from "@/components/ui";
import { usePermissions } from "@/hooks/usePermissions";
import { useI18n } from "@/i18n";

const LIMIT = 50;

export function NasPage() {
  const { t } = useI18n();
  const { canManageNas } = usePermissions();
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [editing, setEditing] = useState<NasItem | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<NasItem | null>(null);
  const [revealed, setRevealed] = useState<{ nasname: string; secret: string } | null>(null);

  const { data, isLoading, error } = useNasList({
    search: search || undefined,
    limit: LIMIT,
    offset,
  });
  const remove = useDeleteNas();
  const reveal = useRevealSecret();

  return (
    <section>
      <header className="page-header">
        <h1>{t("nas.title")}</h1>
        {canManageNas ? (
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            {t("nas.new")}
          </button>
        ) : null}
      </header>

      <p className="alert alert-info">{t("nas.reloadHint")}</p>

      <div className="filters">
        <input
          placeholder={t("common.search")}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
      </div>

      <ErrorBox error={error ?? remove.error ?? reveal.error} />
      {isLoading ? (
        <Spinner />
      ) : (
        <>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>{t("nas.nasname")}</th>
                  <th>{t("nas.shortname")}</th>
                  <th>{t("nas.type")}</th>
                  <th>{t("nas.secret")}</th>
                  <th>{t("nas.coa")}</th>
                  <th>{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {(data?.items ?? []).map((nas) => (
                  <tr key={nas.id}>
                    <td>{nas.nasname}</td>
                    <td>{nas.shortname ?? "–"}</td>
                    <td>{nas.type ?? "–"}</td>
                    <td>
                      {revealed?.nasname === nas.nasname ? (
                        <Copyable value={revealed.secret} />
                      ) : (
                        <>
                          <code>••••••••</code>{" "}
                          {canManageNas ? (
                            <button
                              type="button"
                              className="link"
                              onClick={() =>
                                reveal.mutate(nas.id, { onSuccess: (data) => setRevealed(data) })
                              }
                            >
                              {t("nas.showSecret")}
                            </button>
                          ) : null}
                        </>
                      )}
                    </td>
                    <td>
                      {nas.coa_enabled
                        ? `${t("common.yes")} (${nas.coa_port}${nas.has_coa_secret ? `, ${t("nas.coaSecretSet")}` : ""})`
                        : t("common.no")}
                    </td>
                    <td className="row-actions">
                      {canManageNas ? (
                        <>
                          <button type="button" onClick={() => setEditing(nas)}>
                            {t("common.edit")}
                          </button>
                          <button
                            type="button"
                            className="danger"
                            onClick={() => setConfirmDelete(nas)}
                          >
                            {t("common.delete")}
                          </button>
                        </>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="hint">{t("nas.secretAudit")}</p>
          <Pagination
            total={data?.meta.total ?? 0}
            limit={LIMIT}
            offset={offset}
            onChange={setOffset}
          />
        </>
      )}

      {creating ? <NasDialog onClose={() => setCreating(false)} /> : null}
      {editing ? <NasDialog nas={editing} onClose={() => setEditing(null)} /> : null}
      {confirmDelete ? (
        <ConfirmDialog
          title={t("common.delete")}
          message={`${confirmDelete.nasname}?`}
          onConfirm={() =>
            remove.mutate(confirmDelete.id, { onSuccess: () => setConfirmDelete(null) })
          }
          onCancel={() => setConfirmDelete(null)}
          busy={remove.isPending}
        />
      ) : null}
    </section>
  );
}

function NasDialog({ nas, onClose }: { nas?: NasItem; onClose: () => void }) {
  const { t } = useI18n();
  const create = useCreateNas();
  const update = useUpdateNas();
  const mutation = nas ? update : create;

  const [nasname, setNasname] = useState(nas?.nasname ?? "");
  const [shortname, setShortname] = useState(nas?.shortname ?? "");
  const [type, setType] = useState(nas?.type ?? "other");
  const [description, setDescription] = useState(nas?.description ?? "");
  const [secret, setSecret] = useState("");
  const [coaEnabled, setCoaEnabled] = useState(nas?.coa_enabled ?? false);
  const [coaPort, setCoaPort] = useState(nas?.coa_port ?? 3799);
  const [coaSecret, setCoaSecret] = useState("");
  const [clearCoaSecret, setClearCoaSecret] = useState(false);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const body = {
      nasname,
      shortname: shortname || null,
      type,
      description: description || null,
      secret: secret || (nas ? undefined : ""),
      coa_enabled: coaEnabled,
      coa_port: coaPort,
      coa_secret: coaSecret || null,
      // Das Backend behandelt null als "nicht geändert"; das Entfernen braucht
      // deshalb ein eigenes Kennzeichen.
      clear_coa_secret: clearCoaSecret,
    };
    if (nas) {
      update.mutate({ id: nas.id, body }, { onSuccess: onClose });
    } else {
      create.mutate(body, { onSuccess: onClose });
    }
  };

  return (
    <Modal
      title={nas ? `${t("common.edit")}: ${nas.nasname}` : t("nas.new")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" form="nas-form" className="primary" disabled={mutation.isPending}>
            {t("common.save")}
          </button>
        </>
      }
    >
      <form id="nas-form" onSubmit={submit}>
        <ErrorBox error={mutation.error} />
        <p className="alert alert-info">{t("nas.reloadHint")}</p>
        <Field label={t("nas.nasname")} required>
          {(id) => (
            <input
              id={id}
              value={nasname}
              onChange={(event) => setNasname(event.target.value)}
              required
            />
          )}
        </Field>
        <Field label={t("nas.shortname")}>
          {(id) => (
            <input
              id={id}
              value={shortname}
              onChange={(event) => setShortname(event.target.value)}
            />
          )}
        </Field>
        <Field label={t("nas.type")}>
          {(id) => <input id={id} value={type} onChange={(event) => setType(event.target.value)} />}
        </Field>
        <Field label={t("nas.secret")} required={!nas}>
          {(id) => (
            <input
              id={id}
              type="password"
              value={secret}
              placeholder={nas ? "••••••••" : ""}
              onChange={(event) => setSecret(event.target.value)}
              required={!nas}
            />
          )}
        </Field>
        <Field label={t("nas.description")}>
          {(id) => (
            <input
              id={id}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          )}
        </Field>

        <fieldset>
          <legend>{t("nas.coa")}</legend>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={coaEnabled}
              onChange={(event) => setCoaEnabled(event.target.checked)}
            />
            {t("nas.coaEnabled")}
          </label>
          <Field label={t("nas.coaPort")}>
            {(id) => (
              <input
                id={id}
                type="number"
                value={coaPort}
                onChange={(event) => setCoaPort(Number(event.target.value))}
              />
            )}
          </Field>
          <Field label={t("nas.coaSecret")}>
            {(id) => (
              <input
                id={id}
                type="password"
                value={coaSecret}
                disabled={clearCoaSecret}
                placeholder={nas?.has_coa_secret ? t("nas.coaSecretSet") : ""}
                onChange={(event) => setCoaSecret(event.target.value)}
              />
            )}
          </Field>
          {nas?.has_coa_secret ? (
            <label className="checkbox">
              <input
                type="checkbox"
                checked={clearCoaSecret}
                onChange={(event) => {
                  setClearCoaSecret(event.target.checked);
                  if (event.target.checked) setCoaSecret("");
                }}
              />
              {t("nas.clearCoaSecret")}
            </label>
          ) : null}
        </fieldset>
      </form>
    </Modal>
  );
}

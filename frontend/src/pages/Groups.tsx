import { useState } from "react";

import {
  useCreateGroup,
  useDeleteGroup,
  useDictionary,
  useGroup,
  useGroups,
  useUpdateGroup,
} from "@/api/hooks";
import { MASKED } from "@/api/types";
import type { AttributeInput } from "@/api/types";
import { ConfirmDialog, ErrorBox, Field, Modal, Spinner, WarningList } from "@/components/ui";
import { usePermissions } from "@/hooks/usePermissions";
import { useI18n } from "@/i18n";

/** Genau die Attribute, die der geführte VLAN-Dialog verwaltet. */
const VLAN_ATTRIBUTES = new Set([
  "tunnel-type",
  "tunnel-medium-type",
  "tunnel-private-group-id",
]);

export function GroupsPage() {
  const { t } = useI18n();
  const { canWrite } = usePermissions();
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<{ name: string; members: number } | null>(
    null,
  );

  const { data, isLoading, error } = useGroups(search || undefined);
  const remove = useDeleteGroup();

  return (
    <section>
      <header className="page-header">
        <h1>{t("groups.title")}</h1>
        {canWrite ? (
          <button type="button" className="primary" onClick={() => setShowCreate(true)}>
            {t("groups.new")}
          </button>
        ) : null}
      </header>

      <div className="filters">
        <input
          placeholder={t("common.search")}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      <ErrorBox error={error ?? remove.error} />
      {isLoading ? (
        <Spinner />
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>{t("groups.name")}</th>
                <th>{t("users.vlan")}</th>
                <th>{t("groups.members")}</th>
                <th>{t("common.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((group) => (
                <tr key={group.groupname}>
                  <td>{group.groupname}</td>
                  <td>{group.vlan ?? "–"}</td>
                  <td>{group.members}</td>
                  <td className="row-actions">
                    {canWrite ? (
                      <>
                        <button type="button" onClick={() => setSelected(group.groupname)}>
                          {t("common.edit")}
                        </button>
                        <button
                          type="button"
                          className="danger"
                          onClick={() =>
                            setConfirmDelete({ name: group.groupname, members: group.members })
                          }
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
      )}

      {showCreate ? <GroupDialog onClose={() => setShowCreate(false)} /> : null}
      {selected ? <GroupDialog groupname={selected} onClose={() => setSelected(null)} /> : null}
      {confirmDelete ? (
        <ConfirmDialog
          title={t("common.delete")}
          message={t("groups.deleteConfirm", {
            name: confirmDelete.name,
            count: confirmDelete.members,
          })}
          onConfirm={() =>
            remove.mutate(
              { groupname: confirmDelete.name, force: true },
              { onSuccess: () => setConfirmDelete(null) },
            )
          }
          onCancel={() => setConfirmDelete(null)}
          busy={remove.isPending}
        />
      ) : null}
    </section>
  );
}

function GroupDialog({ groupname, onClose }: { groupname?: string; onClose: () => void }) {
  const { t } = useI18n();
  const existing = useGroup(groupname ?? "", Boolean(groupname));
  const create = useCreateGroup();
  const update = useUpdateGroup(groupname ?? "");
  const dictionary = useDictionary();

  const [name, setName] = useState(groupname ?? "");
  const [vlan, setVlan] = useState<string | null>(null);
  const [expert, setExpert] = useState(false);
  const [checks, setChecks] = useState<AttributeInput[] | null>(null);
  const [replies, setReplies] = useState<AttributeInput[] | null>(null);

  const detail = existing.data;
  const currentVlan = vlan ?? detail?.vlan ?? "";
  // Passwortwerte kommen maskiert aus der API. Sie werden hier nur angezeigt;
  // unverändert zurückgesendet behält das Backend den gespeicherten Wert.
  const currentChecks =
    checks ??
    (detail?.check_attributes.map((a) => ({ attribute: a.attribute, op: a.op, value: a.value })) ??
      []);
  const currentReplies =
    replies ??
    (detail?.reply_attributes
      // Nur die drei Attribute des VLAN-Dialogs ausblenden. Ein Filter über
      // alle "Tunnel-*" löschte beim Speichern etwa Tunnel-Assignment-Id mit.
      .filter((a) => !VLAN_ATTRIBUTES.has(a.attribute.toLowerCase()))
      .map((a) => ({ attribute: a.attribute, op: a.op, value: a.value })) ?? []);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const body = {
      groupname: name,
      vlan: currentVlan || null,
      clear_vlan: currentVlan === "",
      check_attributes: expert ? currentChecks : undefined,
      reply_attributes: expert ? currentReplies : undefined,
    };
    if (groupname) {
      update.mutate(body, { onSuccess: onClose });
    } else {
      create.mutate({ ...body, check_attributes: currentChecks, reply_attributes: currentReplies }, {
        onSuccess: onClose,
      });
    }
  };

  const mutation = groupname ? update : create;

  return (
    <Modal
      title={groupname ? `${t("common.edit")}: ${groupname}` : t("groups.new")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" form="group-form" className="primary" disabled={mutation.isPending}>
            {t("common.save")}
          </button>
        </>
      }
    >
      <form id="group-form" onSubmit={submit}>
        <ErrorBox error={mutation.error ?? existing.error} />
        <WarningList warnings={mutation.data?.warnings} />
        <Field label={t("groups.name")} required>
          {(id) => (
            <input
              id={id}
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
            />
          )}
        </Field>

        <fieldset>
          <legend>{t("groups.vlanWizard")}</legend>
          <p className="hint">{t("groups.vlanHint")}</p>
          <Field label={t("users.vlan")}>
            {(id) => (
              <input
                id={id}
                value={currentVlan}
                onChange={(event) => setVlan(event.target.value)}
              />
            )}
          </Field>
        </fieldset>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={expert}
            onChange={(event) => setExpert(event.target.checked)}
          />
          {t("groups.expert")}
        </label>

        {expert ? (
          <>
            <p className="hint">{t("groups.expertHint")}</p>
            <AttributeEditor
              title={t("users.checkAttributes")}
              rows={currentChecks}
              operators={dictionary.data?.check_operators ?? []}
              names={dictionary.data?.attributes.map((a) => a.name) ?? []}
              onChange={setChecks}
            />
            <AttributeEditor
              title={t("users.replyAttributes")}
              rows={currentReplies}
              operators={dictionary.data?.reply_operators ?? []}
              names={dictionary.data?.attributes.map((a) => a.name) ?? []}
              onChange={setReplies}
            />
          </>
        ) : null}
      </form>
    </Modal>
  );
}

function AttributeEditor({
  title,
  rows,
  operators,
  names,
  onChange,
}: {
  title: string;
  rows: AttributeInput[];
  operators: string[];
  names: string[];
  onChange: (rows: AttributeInput[]) => void;
}) {
  const { t } = useI18n();
  const update = (index: number, patch: Partial<AttributeInput>) =>
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));

  return (
    <fieldset>
      <legend>{title}</legend>
      <datalist id={`attrs-${title}`}>
        {names.map((name) => (
          <option key={name} value={name} />
        ))}
      </datalist>
      {rows.map((row, index) => (
        <div className="attribute-row" key={index}>
          <input
            list={`attrs-${title}`}
            aria-label={t("groups.attribute")}
            value={row.attribute}
            onChange={(event) => update(index, { attribute: event.target.value })}
          />
          <select
            aria-label={t("groups.operator")}
            value={row.op}
            onChange={(event) => update(index, { op: event.target.value })}
          >
            {operators.map((op) => (
              <option key={op} value={op}>
                {op}
              </option>
            ))}
          </select>
          <input
            aria-label={t("groups.value")}
            value={row.value}
            placeholder={row.value === MASKED ? t("groups.maskedValue") : undefined}
            onChange={(event) => update(index, { value: event.target.value })}
          />
          <button
            type="button"
            className="danger"
            onClick={() => onChange(rows.filter((_, i) => i !== index))}
          >
            ×
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => onChange([...rows, { attribute: "", op: operators[0] ?? ":=", value: "" }])}
      >
        {t("groups.addAttribute")}
      </button>
    </fieldset>
  );
}

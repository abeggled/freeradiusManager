import { useState } from "react";

import {
  useCreateGroup,
  useDeleteGroup,
  useDictionary,
  useGroup,
  useGroups,
  useUpdateGroup,
} from "@/api/hooks";
import type { ApiWarning, AttributeInput, GroupDetail } from "@/api/types";
import { AttributeEditor } from "@/components/AttributeEditor";
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
  const { canManageGroups } = usePermissions();
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
        {canManageGroups ? (
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
                    {canManageGroups ? (
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
  // Eine mit Warnung angelegte Gruppe existiert bereits; der Dialog wechselt
  // dann in den Bearbeitungsmodus, damit die Korrektur nicht erneut als POST
  // läuft und an "group_exists" scheitert.
  const [created, setCreated] = useState<string | null>(null);
  // Mit dem Wechsel in den Bearbeitungsmodus wird `update` zur aktiven Mutation;
  // deren `data` ist noch leer und die Warnung der Anlage verschwände sofort.
  const [createdWarnings, setCreatedWarnings] = useState<ApiWarning[] | null>(null);
  // ``created`` zuerst: nach einer Umbenennung mit Warnung zeigt der Dialog auf
  // den neuen Namen, nicht mehr auf den ursprünglich geöffneten.
  const editing = created ?? groupname;
  const existing = useGroup(editing ?? "", Boolean(editing));
  const create = useCreateGroup();
  const update = useUpdateGroup(editing ?? "");
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
    // Der Dialog bleibt offen, wenn der Server Warnungen zurückgibt: sonst
    // verschwände der Hinweis auf ein unbekanntes Attribut ungelesen.
    // Ohne Warnung schliesst der Dialog. Mit Warnung bleibt er offen, damit der
    // Hinweis lesbar ist – und zeigt dann auf den tatsächlich gespeicherten
    // Namen: eine Anlage liefe sonst erneut als POST („group_exists“), eine
    // Umbenennung als PATCH auf den alten Pfad (404).
    const close = (result: GroupDetail) => {
      if (result.warnings.length === 0) {
        onClose();
        return;
      }
      setCreatedWarnings(result.warnings);
      setCreated(result.groupname);
    };
    if (editing) {
      update.mutate(body, { onSuccess: close });
    } else {
      create.mutate(
        { ...body, check_attributes: currentChecks, reply_attributes: currentReplies },
        { onSuccess: close },
      );
    }
  };

  const mutation = editing ? update : create;

  return (
    <Modal
      title={editing ? `${t("common.edit")}: ${editing}` : t("groups.new")}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button
            type="submit"
            form="group-form"
            className="primary"
            // Solange die Details noch laden, sind VLAN und Attribute leer –
            // ein Speichern in diesem Moment löschte die vorhandene Policy.
            disabled={mutation.isPending || existing.isLoading}
          >
            {t("common.save")}
          </button>
        </>
      }
    >
      <form id="group-form" onSubmit={submit}>
        <ErrorBox error={mutation.error ?? existing.error} />
        {existing.isLoading ? <Spinner /> : null}
        <WarningList warnings={mutation.data?.warnings ?? createdWarnings ?? undefined} />
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
            // Solange die Details laden, sind die Sammlungen leer; ein hier
            // begonnener Entwurf überschriebe die geladenen Werte dauerhaft
            // und das Speichern löschte die bestehende Policy.
            disabled={existing.isLoading}
            onChange={(event) => setExpert(event.target.checked)}
          />
          {t("groups.expert")}
        </label>

        {expert && !existing.isLoading ? (
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

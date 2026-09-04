import { useId } from "react";

import type { Membership } from "@/api/types";
import { useI18n } from "@/i18n";

export const DEFAULT_PRIORITY = 1;

/**
 * Mitgliedschaften mit Priorität.
 *
 * Die Priorität bestimmt die Reihenfolge, in der FreeRADIUS die Gruppen eines
 * Benutzers auswertet (`radusergroup.priority`). Ohne Bedienelement liessen sich
 * abweichende Werte nur ausserhalb der Anwendung setzen – und ein Speichern aus
 * der Oberfläche hätte sie überschrieben.
 */
export function MembershipEditor({
  value,
  available,
  onChange,
  label,
  hint,
}: {
  value: Membership[];
  available: string[];
  onChange: (next: Membership[]) => void;
  label: string;
  hint?: string;
}) {
  const { t } = useI18n();
  const id = useId();

  const select = (groupnames: string[]) => {
    // Bestehende Prioritäten bleiben erhalten; nur neue Gruppen bekommen den
    // Standardwert.
    onChange(
      groupnames.map((groupname) => ({
        groupname,
        priority: value.find((m) => m.groupname === groupname)?.priority ?? DEFAULT_PRIORITY,
      })),
    );
  };

  const setPriority = (groupname: string, priority: number) => {
    onChange(value.map((m) => (m.groupname === groupname ? { ...m, priority } : m)));
  };

  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        multiple
        size={Math.min(6, Math.max(3, available.length))}
        value={value.map((m) => m.groupname)}
        onChange={(event) =>
          select(Array.from(event.target.selectedOptions).map((option) => option.value))
        }
      >
        {available.map((groupname) => (
          <option key={groupname} value={groupname}>
            {groupname}
          </option>
        ))}
      </select>
      {hint ? <p className="hint">{hint}</p> : null}
      {value.length > 0 ? (
        <ul className="membership-priorities">
          {value.map((membership) => (
            <li key={membership.groupname}>
              <label htmlFor={`${id}-${membership.groupname}`}>
                {membership.groupname} – {t("groups.priority")}
              </label>
              <input
                id={`${id}-${membership.groupname}`}
                type="number"
                min={0}
                max={10000}
                value={membership.priority}
                onChange={(event) =>
                  setPriority(membership.groupname, Number(event.target.value) || 0)
                }
              />
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

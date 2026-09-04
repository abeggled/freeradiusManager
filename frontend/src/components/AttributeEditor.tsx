import { MASKED } from "@/api/types";
import type { AttributeInput } from "@/api/types";
import { useI18n } from "@/i18n";

/**
 * Freie Bearbeitung von `radcheck`/`radreply`-Tripeln (Expertenmodus).
 *
 * Wird für Gruppen und für einzelne Benutzer verwendet: benutzerspezifische
 * Regeln wie `Simultaneous-Use` oder `Filter-Id` liessen sich sonst nur
 * ausserhalb der Anwendung setzen.
 */
export function AttributeEditor({
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

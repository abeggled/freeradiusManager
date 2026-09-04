import type { Language } from "@/i18n";

export function formatDateTime(value: string | null | undefined, language: Language): string {
  if (!value) return "–";
  const date = new Date(value.endsWith("Z") ? value : `${value}Z`);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(language === "de" ? "de-CH" : "en-GB", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(date);
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "–";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours > 0) return `${hours} h ${minutes} min`;
  if (minutes > 0) return `${minutes} min ${rest} s`;
  return `${rest} s`;
}

/**
 * Byte-Zähler der Accounting-Tabelle sind BIGINT und kommen als Zeichenkette.
 *
 * `Number` würde oberhalb von 2^53 stillschweigend runden; deshalb wird die
 * Grössenordnung mit `BigInt` bestimmt und erst der bereits geteilte Rest als
 * Gleitkommazahl dargestellt.
 */
export function toOctets(value: string | number | null | undefined): bigint {
  if (value === null || value === undefined || value === "") return 0n;
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

export function formatBytes(value: string | number | bigint | null | undefined): string {
  const total = typeof value === "bigint" ? value : toOctets(value as string | number | null);
  if (total <= 0n) return "0 B";
  const units = ["B", "kB", "MB", "GB", "TB"];
  let rest = total;
  let index = 0;
  // Ganzzahlig teilen, solange der Wert gross ist; erst der letzte Schritt
  // rechnet mit Gleitkomma und liegt dann sicher unter 2^53.
  while (rest >= 1024n * 1024n && index < units.length - 1) {
    rest /= 1024n;
    index += 1;
  }
  let size = Number(rest);
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

/** ``datetime-local``-Wert -> ISO-String fuer die API. */
export function toIso(value: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** ISO-String -> Wert fuer ``<input type="datetime-local">``. */
export function toLocalInput(value: string | null | undefined): string {
  if (!value) return "";
  const date = new Date(value.endsWith("Z") ? value : `${value}Z`);
  if (Number.isNaN(date.getTime())) return "";
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

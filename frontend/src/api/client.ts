import type { ApiErrorBody } from "./types";

/**
 * Basis aller API-Aufrufe. Abgeleitet aus dem <base>-Element, das das Backend
 * auf ``FRM_ROOT_PATH`` setzt – sonst zielten die Aufrufe hinter einem
 * Reverse-Proxy-Präfix auf die falsche Adresse.
 */
export const API_BASE = `${document.baseURI.replace(/\/$/, "")}/api/v1`;

const BASE = API_BASE;

/**
 * Wird bei jeder abgelehnten Authentifizierung aufgerufen. Ohne diesen Haken
 * bliebe die Oberfläche nach einer serverseitig beendeten Sitzung sichtbar,
 * während jede weitere Aktion mit 401 scheitert.
 */
let onUnauthenticated: (() => void) | null = null;

/** Fehlercodes, die eine beendete Sitzung bedeuten. */
const SESSION_ENDED_CODES = new Set([
  "error.unauthenticated",
  "error.reauthentication_required",
]);

export function setUnauthenticatedHandler(handler: () => void): void {
  onUnauthenticated = handler;
}

/**
 * Beendet die Oberflächen-Sitzung, ohne auf eine 401-Antwort zu warten.
 *
 * Nötig, wenn eine Aktion die eigene Sitzung serverseitig entwertet – etwa das
 * Einrichten des zweiten Faktors. Ein anschliessendes `/auth/me` ist von der
 * Behandlung oben ausgenommen, die Oberfläche bliebe sonst vollständig
 * gerendert, aber unbenutzbar.
 */
export function endSession(): void {
  onUnauthenticated?.();
}

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details: Record<string, unknown>;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message || body.code);
    this.name = "ApiError";
    this.status = status;
    this.code = body.code;
    this.details = body.details ?? {};
  }
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  formData?: FormData;
  raw?: boolean;
  /**
   * Kennzeichnet Abfragen, die ohne Zutun der Benutzerin laufen. Das Backend
   * verlängert die Sitzung dann nicht – sonst liefe der Idle-Timeout nie ab,
   * solange ein Dashboard offen steht.
   */
  background?: boolean;
}

export function buildQuery(
  query: Record<string, string | number | boolean | undefined | null> = {},
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

/**
 * Zentraler Fetch-Wrapper. Session-Cookies werden mitgesendet; Fehler kommen
 * einheitlich als {code, message, details} zurueck (Spezifikation 6.3).
 */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, query, formData, raw, background } = options;
  const headers: Record<string, string> = {};
  if (!formData && body !== undefined) headers["Content-Type"] = "application/json";
  if (background) headers["X-Background-Refresh"] = "1";

  const response = await fetch(`${BASE}${path}${buildQuery(query)}`, {
    method,
    credentials: "same-origin",
    headers: Object.keys(headers).length > 0 ? headers : undefined,
    body: formData ?? (body === undefined ? undefined : JSON.stringify(body)),
  });

  if (response.status === 204) return undefined as T;

  if (!response.ok) {
    let payload: ApiErrorBody = {
      code: "error.generic",
      message: response.statusText,
      details: {},
    };
    try {
      payload = (await response.json()) as ApiErrorBody;
    } catch {
      /* Antwort ohne JSON-Körper */
    }
    // Nur eine tatsächlich beendete Sitzung führt zur Anmeldemaske. Ein
    // falsches aktuelles Passwort oder ein falscher TOTP-Code sind 401, aber
    // behebbare Formularfehler – sie dürfen die Sitzung nicht verwerfen.
    // Die Sitzungsabfrage selbst bleibt aussen vor, sonst drehte sie sich im
    // Kreis.
    if (
      response.status === 401 &&
      SESSION_ENDED_CODES.has(payload.code) &&
      !path.startsWith("/auth/login") &&
      path !== "/auth/me"
    ) {
      onUnauthenticated?.();
    }
    throw new ApiError(response.status, payload);
  }

  if (raw) return (await response.text()) as T;
  return (await response.json()) as T;
}

/** Loest einen Datei-Download aus (CSV-Export und Vorlagen, FR-8). */
export async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(`${BASE}${path}`, { credentials: "same-origin" });
  if (!response.ok) {
    // Wie in request(): eine abgelaufene Sitzung führt zur Anmeldemaske statt
    // in eine stille Fehlermeldung.
    // Downloads kennen keinen Fehlerkörper; ein 401 bedeutet hier immer eine
    // beendete Sitzung.
    if (response.status === 401) onUnauthenticated?.();
    throw new ApiError(response.status, {
      code: "error.generic",
      message: response.statusText,
      details: {},
    });
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

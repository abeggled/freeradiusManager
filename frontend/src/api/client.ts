import type { ApiErrorBody } from "./types";

const BASE = "/api/v1";

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
    throw new ApiError(response.status, payload);
  }

  if (raw) return (await response.text()) as T;
  return (await response.json()) as T;
}

/** Loest einen Datei-Download aus (CSV-Export und Vorlagen, FR-8). */
export async function download(path: string, filename: string): Promise<void> {
  const response = await fetch(`${BASE}${path}`, { credentials: "same-origin" });
  if (!response.ok) {
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

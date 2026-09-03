/** Typen entsprechend den Pydantic-Schemas des Backends (siehe /api/openapi.json). */

/** Platzhalter, den das Backend anstelle von Passwortwerten liefert. */
export const MASKED = "********";

export type Role = "administrator" | "operator" | "auditor";
export type SubjectType = "user" | "device";
export type CredentialType = "cleartext" | "nt" | "both";
export type UserStatus = "active" | "disabled" | "expired" | "no_credentials";

export interface ApiErrorBody {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface ApiWarning {
  code: string;
  message: string;
  attribute?: string | null;
}

export interface PageMeta {
  total: number;
  limit: number;
  offset: number;
}

export interface Paged<T> {
  items: T[];
  meta: PageMeta;
}

export interface CursorMeta {
  limit: number;
  next_cursor: string | null;
  approximate_total?: number | null;
}

export interface CursorPaged<T> {
  items: T[];
  meta: CursorMeta;
}

export interface Attribute {
  id: number;
  attribute: string;
  op: string;
  value: string;
}

export interface AttributeInput {
  attribute: string;
  op: string;
  value: string;
}

export interface Membership {
  groupname: string;
  priority: number;
}

export interface SubjectMeta {
  display_name?: string | null;
  note?: string | null;
  owner?: string | null;
  device_type?: string | null;
  location?: string | null;
  inventory_no?: string | null;
}

export interface UserListItem {
  username: string;
  subject_type: SubjectType;
  display_name: string | null;
  owner: string | null;
  note: string | null;
  location: string | null;
  device_type: string | null;
  inventory_no: string | null;
  groups: string[];
  status: UserStatus;
  expires_at: string | null;
  credential_type: CredentialType | null;
  has_metadata: boolean;
}

export interface UserDetail extends UserListItem {
  check_attributes: Attribute[];
  reply_attributes: Attribute[];
  memberships: Membership[];
  vlan: string | null;
  active_sessions: number;
  last_auth: string | null;
  last_auth_reply: string | null;
  created_at: string | null;
  updated_at: string | null;
  warnings: ApiWarning[];
}

export interface GroupListItem {
  groupname: string;
  members: number;
  vlan: string | null;
}

export interface GroupDetail extends GroupListItem {
  check_attributes: Attribute[];
  reply_attributes: Attribute[];
  warnings: ApiWarning[];
}

export interface DictionaryEntry {
  name: string;
  kind: string;
  value_type: string;
  values: string[];
  description: string | null;
}

export interface DictionaryResponse {
  attributes: DictionaryEntry[];
  check_operators: string[];
  reply_operators: string[];
}

export interface NasItem {
  id: number;
  nasname: string;
  shortname: string | null;
  type: string | null;
  ports: number | null;
  server: string | null;
  description: string | null;
  secret: string | null;
  coa_enabled: boolean;
  coa_port: number;
  has_coa_secret: boolean;
}

export interface SessionItem {
  radacctid: number;
  acctsessionid: string;
  acctuniqueid: string;
  username: string;
  nasipaddress: string;
  nasportid: string | null;
  nasporttype: string | null;
  callingstationid: string;
  calledstationid: string;
  framedipaddress: string | null;
  acctstarttime: string | null;
  acctupdatetime: string | null;
  acctstoptime: string | null;
  acctsessiontime: number | null;
  acctinputoctets: number | null;
  acctoutputoctets: number | null;
  acctterminatecause: string | null;
  active: boolean;
  ssid: string | null;
  nas_shortname: string | null;
}

export interface AuthLogItem {
  id: number;
  username: string;
  reply: string;
  authdate: string;
  accepted: boolean;
}

export interface DiagnosisHint {
  code: string;
  message: string;
  severity: "info" | "warning" | "error" | "success";
}

export interface Diagnosis {
  subject: string;
  exists: boolean;
  status: string;
  hints: DiagnosisHint[];
  attempts: AuthLogItem[];
  last_session: SessionItem | null;
  groups: string[];
  vlan: string | null;
}

export interface Stats {
  computed_at: string | null;
  stale: boolean;
  active_sessions: number;
  sessions_started: number;
  input_octets: number;
  output_octets: number;
  accepts: number;
  rejects: number;
  top_users: { username: string; sessions: number }[];
  top_nas: { nasipaddress: string; sessions: number }[];
  top_rejected: { username: string; attempts: number }[];
  users_total: number;
  devices_total: number;
  groups_total: number;
  nas_total: number;
}

export interface Account {
  id: number;
  username: string;
  email: string | null;
  display_name: string | null;
  role: Role;
  is_active: boolean;
  totp_enabled: boolean;
  language: string;
  last_login_at: string | null;
  created_at: string | null;
}

export interface AuditItem {
  id: number;
  ts: string;
  actor_name: string;
  actor_ip: string | null;
  action: string;
  object_type: string;
  object_id: string | null;
  result: string;
  message: string | null;
  before: unknown;
  after: unknown;
}

export interface LoginResponse {
  status: "authenticated" | "totp_required" | "totp_setup_required";
  challenge: string | null;
  account: Account | null;
}

export interface ImportRow {
  line: number;
  action: "create" | "update" | "skip" | "error";
  username: string;
  message: string | null;
  values: Record<string, unknown>;
}

export interface ImportReport {
  dry_run: boolean;
  total: number;
  to_create: number;
  to_update: number;
  errors: number;
  rows: ImportRow[];
}

export interface BulkResult {
  requested: number;
  succeeded: number;
  failed: number;
  errors: { username: string; error: string }[];
}

export interface SettingsResponse {
  values: Record<string, unknown>;
  options: {
    mac_format: { key: string; example: string }[];
    credential_type: string[];
  };
}

export interface CoAResponse {
  ok: boolean;
  action: string;
  nas: string;
  code: string | null;
  message: string;
  attributes: Record<string, string>;
}

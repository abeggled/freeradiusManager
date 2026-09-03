import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseMutationResult } from "@tanstack/react-query";

import { request } from "./client";
import type {
  Account,
  AuditItem,
  AuthLogItem,
  BulkResult,
  CoAResponse,
  CursorPaged,
  Diagnosis,
  DictionaryResponse,
  GroupDetail,
  GroupListItem,
  ImportReport,
  LoginResponse,
  NasItem,
  Paged,
  SessionItem,
  SettingsResponse,
  Stats,
  UserDetail,
  UserListItem,
} from "./types";

type Query = Record<string, string | number | boolean | undefined | null>;

export const queryKeys = {
  me: ["me"] as const,
  stats: ["stats"] as const,
  users: (query: Query) => ["users", query] as const,
  user: (username: string) => ["user", username] as const,
  devices: (query: Query) => ["devices", query] as const,
  device: (mac: string) => ["device", mac] as const,
  macFormats: ["mac-formats"] as const,
  groups: (search?: string) => ["groups", search ?? ""] as const,
  group: (name: string) => ["group", name] as const,
  dictionary: ["dictionary"] as const,
  nas: (query: Query) => ["nas", query] as const,
  sessions: (query: Query) => ["sessions", query] as const,
  terminateCauses: ["terminate-causes"] as const,
  authlog: (query: Query) => ["authlog", query] as const,
  diagnosis: (subject: string) => ["diagnosis", subject] as const,
  audit: (query: Query) => ["audit", query] as const,
  accounts: (query: Query) => ["accounts", query] as const,
  settings: ["settings"] as const,
  oidcStatus: ["oidc-status"] as const,
};

// --- Authentifizierung ----------------------------------------------------

export function useMe() {
  return useQuery({
    queryKey: queryKeys.me,
    queryFn: () => request<Account>("/auth/me"),
    retry: false,
    staleTime: 60_000,
  });
}

export function useOidcStatus() {
  return useQuery({
    queryKey: queryKeys.oidcStatus,
    queryFn: () => request<{ enabled: boolean; issuer: string | null }>("/auth/oidc/status"),
    staleTime: Infinity,
  });
}

export function useLogin() {
  return useMutation({
    mutationFn: (body: { username: string; password: string }) =>
      request<LoginResponse>("/auth/login", { method: "POST", body }),
  });
}

export function useLoginTotp() {
  return useMutation({
    mutationFn: (body: { challenge: string; totp_code: string }) =>
      request<LoginResponse>("/auth/login/totp", { method: "POST", body }),
  });
}

export function useTotpEnroll() {
  return useMutation({
    // Die Challenge geht in den Rumpf, nicht in die URL: sonst stünde dieses
    // kurzlebige Zugangsmerkmal in jedem Zugriffsprotokoll.
    mutationFn: (challenge: string) =>
      request<{ secret: string; provisioning_uri: string }>("/auth/totp/enroll", {
        method: "POST",
        body: { challenge },
      }),
  });
}

export function useTotpConfirm() {
  return useMutation({
    mutationFn: (body: { challenge: string; totp_code: string }) =>
      request<LoginResponse>("/auth/totp/confirm", { method: "POST", body }),
  });
}

export function useLogout() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => request<void>("/auth/logout", { method: "POST" }),
    onSuccess: () => client.clear(),
  });
}

// --- Benutzer und Geräte --------------------------------------------------

export function useUsers(query: Query) {
  return useQuery({
    queryKey: queryKeys.users(query),
    queryFn: () => request<Paged<UserListItem>>("/users", { query }),
  });
}

export function useUser(username: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.user(username),
    queryFn: () => request<UserDetail>(`/users/${encodeURIComponent(username)}`),
    enabled: enabled && Boolean(username),
  });
}

export function useDevices(query: Query) {
  return useQuery({
    queryKey: queryKeys.devices(query),
    queryFn: () => request<Paged<UserListItem>>("/devices", { query }),
  });
}

export function useDevice(mac: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.device(mac),
    queryFn: () => request<UserDetail>(`/devices/${encodeURIComponent(mac)}`),
    enabled: enabled && Boolean(mac),
  });
}

export function useMacFormats() {
  return useQuery({
    queryKey: queryKeys.macFormats,
    queryFn: () =>
      request<{ formats: { key: string; example: string }[]; active: string }>(
        "/devices/mac-formats",
      ),
    staleTime: 300_000,
  });
}

function invalidator(client: ReturnType<typeof useQueryClient>, prefixes: string[]) {
  return () => {
    for (const prefix of prefixes) {
      void client.invalidateQueries({ queryKey: [prefix] });
    }
  };
}

export function useCreateUser() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) => request<UserDetail>("/users", { method: "POST", body }),
    onSuccess: invalidator(client, ["users", "user", "stats"]),
  });
}

export function useUpdateUser(username: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) =>
      request<UserDetail>(`/users/${encodeURIComponent(username)}`, { method: "PATCH", body }),
    onSuccess: invalidator(client, ["users", "user"]),
  });
}

export function useSetUserPassword(username: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { password: string; credential_type?: string | null }) =>
      request<void>(`/users/${encodeURIComponent(username)}/password`, { method: "PUT", body }),
    // Der Status wechselt dabei von "no_credentials" zu "active"; Detail- und
    // Listenansicht müssen das sofort zeigen.
    onSuccess: invalidator(client, ["users", "user", "devices", "device"]),
  });
}

export function useToggleUser() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ username, disabled }: { username: string; disabled: boolean }) =>
      request<void>(
        `/users/${encodeURIComponent(username)}/${disabled ? "disable" : "enable"}`,
        { method: "POST" },
      ),
    onSuccess: invalidator(client, ["users", "user", "devices", "device"]),
  });
}

export function useDeleteUser() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (username: string) =>
      request<void>(`/users/${encodeURIComponent(username)}`, { method: "DELETE" }),
    onSuccess: invalidator(client, ["users", "user", "devices", "stats"]),
  });
}

export function useCreateDevice() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) => request<UserDetail>("/devices", { method: "POST", body }),
    onSuccess: invalidator(client, ["devices", "device", "stats"]),
  });
}

export function useUpdateDevice(mac: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) =>
      request<UserDetail>(`/devices/${encodeURIComponent(mac)}`, { method: "PATCH", body }),
    onSuccess: invalidator(client, ["devices", "device"]),
  });
}

export function useDeleteDevice() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (mac: string) =>
      request<void>(`/devices/${encodeURIComponent(mac)}`, { method: "DELETE" }),
    onSuccess: invalidator(client, ["devices", "device", "stats"]),
  });
}

export function useBulkAction(): UseMutationResult<BulkResult, Error, { body: unknown; query: Query }> {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ body, query }) =>
      request<BulkResult>("/users/bulk", { method: "POST", body, query }),
    onSuccess: invalidator(client, ["users", "devices", "stats"]),
  });
}

export function useImportCsv() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ kind, file, dryRun }: { kind: "user" | "device"; file: File; dryRun: boolean }) => {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("dry_run", String(dryRun));
      return request<ImportReport>(`/imports/${kind}`, { method: "POST", formData });
    },
    onSuccess: invalidator(client, ["users", "devices", "stats"]),
  });
}

// --- Gruppen --------------------------------------------------------------

export function useGroups(search?: string) {
  return useQuery({
    queryKey: queryKeys.groups(search),
    queryFn: () => request<GroupListItem[]>("/groups", { query: { search } }),
  });
}

export function useGroup(groupname: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.group(groupname),
    queryFn: () => request<GroupDetail>(`/groups/${encodeURIComponent(groupname)}`),
    enabled: enabled && Boolean(groupname),
  });
}

export function useDictionary() {
  return useQuery({
    queryKey: queryKeys.dictionary,
    queryFn: () => request<DictionaryResponse>("/groups/dictionary"),
    staleTime: 600_000,
  });
}

export function useCreateGroup() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) => request<GroupDetail>("/groups", { method: "POST", body }),
    onSuccess: invalidator(client, ["groups", "group"]),
  });
}

export function useUpdateGroup(groupname: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) =>
      request<GroupDetail>(`/groups/${encodeURIComponent(groupname)}`, { method: "PATCH", body }),
    onSuccess: invalidator(client, ["groups", "group"]),
  });
}

export function useDeleteGroup() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ groupname, force }: { groupname: string; force: boolean }) =>
      request<{ removed_memberships: number }>(`/groups/${encodeURIComponent(groupname)}`, {
        method: "DELETE",
        query: { force },
      }),
    onSuccess: invalidator(client, ["groups", "group", "users"]),
  });
}

// --- NAS und CoA ----------------------------------------------------------

export function useNasList(query: Query) {
  return useQuery({
    queryKey: queryKeys.nas(query),
    queryFn: () => request<Paged<NasItem>>("/nas", { query }),
  });
}

export function useCreateNas() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) => request<NasItem>("/nas", { method: "POST", body }),
    onSuccess: invalidator(client, ["nas", "stats"]),
  });
}

export function useUpdateNas() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: unknown }) =>
      request<NasItem>(`/nas/${id}`, { method: "PATCH", body }),
    onSuccess: invalidator(client, ["nas"]),
  });
}

export function useDeleteNas() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => request<void>(`/nas/${id}`, { method: "DELETE" }),
    onSuccess: invalidator(client, ["nas", "stats"]),
  });
}

export function useRevealSecret() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      request<{ nasname: string; secret: string }>(`/nas/${id}/secret`, { method: "POST" }),
    onSuccess: invalidator(client, ["audit"]),
  });
}

export function useCoA() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) => request<CoAResponse>("/nas/coa", { method: "POST", body }),
    onSuccess: invalidator(client, ["sessions", "audit"]),
  });
}

// --- Sessions, Auth-Log, Audit -------------------------------------------

export function useSessions(query: Query) {
  return useQuery({
    queryKey: queryKeys.sessions(query),
    queryFn: () => request<CursorPaged<SessionItem>>("/sessions", { query }),
  });
}

export function useTerminateCauses() {
  return useQuery({
    queryKey: queryKeys.terminateCauses,
    queryFn: () => request<string[]>("/sessions/terminate-causes"),
    staleTime: 300_000,
  });
}

export function useAuthLog(query: Query) {
  return useQuery({
    queryKey: queryKeys.authlog(query),
    queryFn: () => request<CursorPaged<AuthLogItem>>("/authlog", { query }),
  });
}

export function useDiagnosis(subject: string) {
  return useQuery({
    queryKey: queryKeys.diagnosis(subject),
    queryFn: () => request<Diagnosis>(`/authlog/diagnose/${encodeURIComponent(subject)}`),
    enabled: Boolean(subject),
  });
}

export function useAudit(query: Query) {
  return useQuery({
    queryKey: queryKeys.audit(query),
    queryFn: () => request<Paged<AuditItem>>("/audit", { query }),
  });
}

// --- Konten, Einstellungen, Statistik ------------------------------------

export function useAccounts(query: Query) {
  return useQuery({
    queryKey: queryKeys.accounts(query),
    queryFn: () => request<Paged<Account>>("/accounts", { query }),
  });
}

export function useCreateAccount() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: unknown) => request<Account>("/accounts", { method: "POST", body }),
    onSuccess: invalidator(client, ["accounts"]),
  });
}

export function useUpdateAccount() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: unknown }) =>
      request<Account>(`/accounts/${id}`, { method: "PATCH", body }),
    onSuccess: invalidator(client, ["accounts"]),
  });
}

export function useDeleteAccount() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => request<void>(`/accounts/${id}`, { method: "DELETE" }),
    onSuccess: invalidator(client, ["accounts"]),
  });
}

export function useLinkOidc() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, subject }: { id: number; subject: string | null }) =>
      request<Account>(`/accounts/${id}/oidc`, {
        method: "PUT",
        body: { oidc_subject: subject },
      }),
    onSuccess: invalidator(client, ["accounts"]),
  });
}

export function useChangeOwnPassword() {
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      request<void>("/accounts/me/password", { method: "PUT", body }),
  });
}

export function useOwnTotpEnroll() {
  return useMutation({
    mutationFn: () =>
      request<{ secret: string; provisioning_uri: string }>("/auth/me/totp/enroll", {
        method: "POST",
      }),
  });
}

export function useOwnTotpConfirm() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { code: string }) =>
      request<void>("/auth/me/totp/confirm", { method: "POST", body }),
    onSuccess: invalidator(client, ["me"]),
  });
}

export function useSettings() {
  return useQuery({
    queryKey: queryKeys.settings,
    queryFn: () => request<SettingsResponse>("/settings"),
  });
}

export function useUpdateSettings() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      request<Record<string, unknown>>("/settings", { method: "PUT", body }),
    onSuccess: invalidator(client, ["settings", "mac-formats"]),
  });
}

export function useStats() {
  return useQuery({
    queryKey: queryKeys.stats,
    // Als Hintergrundlauf gekennzeichnet: das offene Dashboard soll den
    // Idle-Timeout der Sitzung nicht aushebeln.
    queryFn: () => request<Stats>("/stats", { background: true }),
    refetchInterval: 60_000,
  });
}

export function useSessionDetail(radacctid: number | null) {
  return useQuery({
    queryKey: ["session", radacctid],
    queryFn: () => request<SessionItem>(`/sessions/${radacctid}`),
    enabled: radacctid !== null,
  });
}

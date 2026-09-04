import { useMe } from "@/api/hooks";
import type { Role } from "@/api/types";

export interface Permissions {
  role: Role | null;
  /** Administratoren und Operatoren dürfen schreiben (Spezifikation, Abschnitt 2). */
  canWrite: boolean;
  /** NAS-Clients und Shared Secrets sind Administratoren vorbehalten. */
  canManageNas: boolean;
  /** Gruppen wirken auf alle Mitglieder; das Backend verlangt Administrator. */
  canManageGroups: boolean;
  isAdmin: boolean;
}

/**
 * Sichtbarkeit von Bedienelementen. Die Durchsetzung bleibt im Backend – dies
 * verhindert nur, dass ein Auditor Schaltflächen angeboten bekommt, die
 * zwangsläufig mit 403 enden.
 */
export function usePermissions(): Permissions {
  const me = useMe();
  const role = me.data?.role ?? null;
  return {
    role,
    canWrite: role === "administrator" || role === "operator",
    canManageNas: role === "administrator",
    canManageGroups: role === "administrator",
    isAdmin: role === "administrator",
  };
}

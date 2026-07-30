import { useQuery } from '@tanstack/react-query'
import { fetchCurrentUser } from '../api/rbac'

/**
 * The caller's effective permissions (#222).
 *
 * This project has no Context or Redux by design (ui/CLAUDE.md), so the React
 * Query cache is the store: every component calls this hook and shares one
 * cached /auth/me response instead of the answer being threaded down as props.
 *
 * Hiding a menu is a convenience, never a security boundary — the server decides.
 * When the RBAC tables are absent the API omits effective_permissions, and this
 * hook then reports everything as allowed, which is the pre-RBAC behavior.
 */
export function usePermissions() {
  const { data, isLoading } = useQuery({
    queryKey: ['current-user'],
    queryFn: fetchCurrentUser,
    // Permissions change rarely; a stale value only affects what is shown, and
    // the server re-checks every request anyway.
    staleTime: 60_000,
  })

  const list = data?.effective_permissions
  const isSuperuser = data?.is_superuser === true
  // No list means the server did not report one (RBAC tables missing, or an old
  // API): fall open rather than hiding the whole UI.
  const unrestricted = isSuperuser || list === undefined

  const can = (permission: string): boolean => {
    if (unrestricted) return true
    return (list ?? []).includes(permission)
  }

  /** True when any of the area's verbs is granted — used to show/hide a menu. */
  const canArea = (area: string): boolean => {
    if (unrestricted) return true
    return (list ?? []).some((p) => p.startsWith(`${area}:`))
  }

  return {
    user: data,
    isLoading,
    isSuperuser,
    unrestricted,
    permissions: list ?? [],
    can,
    canArea,
  }
}

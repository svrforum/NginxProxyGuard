// RBAC types (#222). The permission vocabulary is fetched from the server rather
// than hardcoded here — see fetchPermissionAreas — so the role editor cannot
// drift from what the API actually enforces.

export interface PermissionArea {
  Key: string
  Verbs: string[]
}

export interface PermissionAreasResponse {
  areas: PermissionArea[]
  permissions: string[]
}

export interface Role {
  id: string
  name: string
  description: string
  is_superuser: boolean
  is_builtin: boolean
  permissions: string[] | null
  user_count: number
  created_at: string
  updated_at: string
}

export interface CreateRoleRequest {
  name: string
  description: string
  permissions: string[]
}

export interface UpdateRoleRequest {
  name?: string
  description?: string
  permissions?: string[]
}

export interface UserSummary {
  id: string
  username: string
  role_id?: string
  role_name: string
  legacy_role: string
  is_superuser: boolean
  totp_enabled: boolean
  must_change_password: boolean
  last_login_at?: string
  login_count: number
  created_at: string
  /** Deleting a user cascades their API tokens — shown in the confirmation. */
  api_token_count: number
}

export interface CreateUserRequest {
  username: string
  password: string
  role_id: string
}

/** GET /auth/me. effective_permissions is absent on installs where the RBAC
 *  tables are missing, in which case the UI treats the user as unrestricted. */
export interface CurrentUser {
  id: string
  username: string
  role: string
  role_id?: string
  language?: string
  font_family?: string
  is_initial_setup?: boolean
  must_change_password?: boolean
  totp_enabled?: boolean
  effective_permissions?: string[]
  is_superuser?: boolean
}

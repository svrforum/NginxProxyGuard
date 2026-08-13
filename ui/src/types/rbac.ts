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
  /** Optional. Without it the account gets <username>@localhost, which no
   *  identity provider can match when linking an SSO sign-in. (#240) */
  email?: string
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

export interface UserTokenInfo {
  id: string
  name: string
  token_prefix: string
  permissions: string[]
  allowed_ips?: string[]
  expires_at?: string
  last_used_at?: string
  last_used_ip?: string
  use_count: number
  is_active: boolean
  revoked_at?: string
  created_at: string
}

/** What the admin panel shows when an account name is opened. */
/** An identity provider this account can sign in through. (#227) */
export interface UserIdentityInfo {
  provider_name: string
  provider_slug: string
  email: string
  last_login_at?: string
  linked_at: string
}

export interface UserDetail extends UserSummary {
  /** The address SSO links this account by. (#240) */
  email: string
  last_login_ip?: string
  totp_verified_at?: string
  updated_at: string
  /** The set actually enforced — expanded, so it includes what a legacy coarse
   *  scope reaches and everything an administrator holds without stored rows. */
  effective_permissions: string[] | null
  /** The role's stored rows, for comparison with the above. */
  role_permissions: string[] | null
  tokens: UserTokenInfo[] | null
  active_sessions: number
  /** Identity providers this account may sign in through. (#227) */
  linked_identities: UserIdentityInfo[] | null
}

import { apiGet, apiPost, apiPut, apiDelete } from './client'
import type {
  CreateRoleRequest,
  CreateUserRequest,
  CurrentUser,
  PermissionAreasResponse,
  Role,
  UpdateRoleRequest,
  UserSummary,
} from '../types/rbac'

const API_BASE = '/api/v1'

/** The permission vocabulary, straight from the server, so the role editor can
 *  never offer a checkbox the API does not know about. (#222) */
export async function fetchPermissionAreas(): Promise<PermissionAreasResponse> {
  return apiGet<PermissionAreasResponse>(`${API_BASE}/permission-areas`)
}

export async function listRoles(): Promise<{ data: Role[] }> {
  return apiGet<{ data: Role[] }>(`${API_BASE}/roles`)
}

export async function createRole(data: CreateRoleRequest): Promise<Role> {
  return apiPost<Role>(`${API_BASE}/roles`, data)
}

export async function updateRole(id: string, data: UpdateRoleRequest): Promise<Role> {
  return apiPut<Role>(`${API_BASE}/roles/${id}`, data)
}

export async function deleteRole(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/roles/${id}`)
}

export async function listUsers(): Promise<{ data: UserSummary[] }> {
  return apiGet<{ data: UserSummary[] }>(`${API_BASE}/users`)
}

export async function createUser(data: CreateUserRequest): Promise<UserSummary> {
  return apiPost<UserSummary>(`${API_BASE}/users`, data)
}

export async function assignUserRole(id: string, roleId: string): Promise<UserSummary> {
  return apiPut<UserSummary>(`${API_BASE}/users/${id}/role`, { role_id: roleId })
}

export async function setUserPassword(id: string, password: string): Promise<void> {
  return apiPut<void>(`${API_BASE}/users/${id}/password`, { password })
}

export async function deleteUser(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/users/${id}`)
}

export async function endUserSessions(id: string): Promise<void> {
  return apiPost<void>(`${API_BASE}/users/${id}/end-sessions`)
}

/** The canonical who-am-I, carrying the caller's effective permissions. */
export async function fetchCurrentUser(): Promise<CurrentUser> {
  return apiGet<CurrentUser>(`${API_BASE}/auth/me`)
}

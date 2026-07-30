import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  assignUserRole,
  createUser,
  deleteUser,
  listRoles,
  listUsers,
  setUserPassword,
} from '../../api/rbac'
import type { UserSummary } from '../../types/rbac'
import { usePermissions } from '../../hooks/usePermissions'
import { AddButton, EmptyState, EntityCard, IconButton, TrashIcon } from '../common/listui'
import { ModalShell } from '../common/ModalShell'
import { UserDetailModal } from './UserDetailModal'

function roleLabel(name: string, t: (k: string, o?: Record<string, unknown>) => string): string {
  if (name.startsWith('builtin.')) {
    return t(`roles.builtin.${name.slice('builtin.'.length)}`, { defaultValue: name })
  }
  return name || '—'
}

export default function UserManager() {
  const { t } = useTranslation(['settings', 'common'])
  // Narrow wrapper: roleLabel only needs (key, options) -> string, and i18next's
  // TFunction generic does not structurally match that signature.
  const tr = (k: string, o?: Record<string, unknown>) => String(t(k, o))
  const queryClient = useQueryClient()
  const { user: me } = usePermissions()

  const [creating, setCreating] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRoleId, setNewRoleId] = useState('')
  const [deleting, setDeleting] = useState<UserSummary | null>(null)
  const [resetting, setResetting] = useState<UserSummary | null>(null)
  const [resetPassword, setResetPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [detailUserId, setDetailUserId] = useState<string | null>(null)

  const { data: usersData, isLoading } = useQuery({ queryKey: ['users'], queryFn: listUsers })
  const { data: rolesData } = useQuery({ queryKey: ['roles'], queryFn: listRoles })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users'] })
  const fail = (e: Error) => setError(e.message)

  const createMutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      invalidate()
      setCreating(false)
      setNewUsername('')
      setNewPassword('')
      setError(null)
    },
    onError: fail,
  })
  const assignMutation = useMutation({
    mutationFn: ({ id, roleId }: { id: string; roleId: string }) => assignUserRole(id, roleId),
    onSuccess: invalidate,
    onError: fail,
  })
  const passwordMutation = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) => setUserPassword(id, password),
    onSuccess: () => { invalidate(); setResetting(null); setResetPassword(''); setError(null) },
    onError: fail,
  })
  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => { invalidate(); setDeleting(null); setError(null) },
    onError: (e: Error) => { fail(e); setDeleting(null) },
  })

  const roles = rolesData?.data ?? []

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('users.title')}</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">{t('users.subtitle')}</p>
        </div>
        <AddButton onClick={() => { setCreating(true); setNewRoleId(roles[0]?.id ?? ''); setError(null) }}>
          {t('users.add')}
        </AddButton>
      </div>

      {error && (
        <div className="mb-3 rounded-lg bg-red-50 px-4 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
          {error}
        </div>
      )}

      {isLoading ? (
        <p className="text-sm text-slate-500">{t('common:loading', { defaultValue: 'Loading…' })}</p>
      ) : !usersData?.data?.length ? (
        <EmptyState>{t('users.empty')}</EmptyState>
      ) : (
        <div className="space-y-3" data-testid="user-list">
          {usersData.data.map((u) => {
            const isSelf = me?.id === u.id
            return (
              <EntityCard key={u.id}>
                <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setDetailUserId(u.id)}
                        className="truncate text-sm font-semibold text-slate-900 hover:text-indigo-600 hover:underline dark:text-white dark:hover:text-indigo-400"
                        title={t('users.openDetail')}
                      >
                        {u.username}
                      </button>
                      {isSelf && (
                        <span className="inline-flex items-center rounded-md bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-indigo-700 dark:bg-indigo-900/20 dark:text-indigo-300">
                          {t('users.you')}
                        </span>
                      )}
                      {u.totp_enabled && (
                        <span className="inline-flex items-center rounded-md bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300">
                          2FA
                        </span>
                      )}
                      {u.must_change_password && (
                        <span className="inline-flex items-center rounded-md bg-amber-50 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
                          {t('users.mustChangePassword')}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-slate-500 dark:text-slate-400">
                      <span>
                        {u.last_login_at
                          ? t('users.lastLoginAt', { when: new Date(u.last_login_at).toLocaleString() })
                          : t('users.neverLoggedIn')}
                      </span>
                      {!!u.api_token_count && (
                        <>
                          <span className="text-slate-300 dark:text-slate-600">·</span>
                          <span>{t('users.apiTokens', { count: u.api_token_count })}</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Role picker. Changing your own role is refused server-side, so
                      it is disabled here rather than offering an action that 409s. */}
                  <select
                    aria-label={`role-for-${u.username}`}
                    value={u.role_id ?? ''}
                    disabled={isSelf || assignMutation.isPending}
                    onChange={(e) => assignMutation.mutate({ id: u.id, roleId: e.target.value })}
                    className="rounded-lg border border-slate-300 px-2 py-1.5 text-xs disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700 dark:text-white"
                  >
                    {roles.map((r) => (
                      <option key={r.id} value={r.id}>{roleLabel(r.name, tr)}</option>
                    ))}
                  </select>

                  <div className="flex items-center gap-0.5">
                    <IconButton onClick={() => { setResetting(u); setResetPassword(''); setError(null) }} title={t('users.resetPassword')}>
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                      </svg>
                    </IconButton>
                    <IconButton
                      onClick={() => { setDeleting(u); setError(null) }}
                      disabled={isSelf}
                      title={isSelf ? t('users.cannotDeleteSelf') : t('common:buttons.delete')}
                      variant="danger"
                    >
                      <TrashIcon />
                    </IconButton>
                  </div>
                </div>
              </EntityCard>
            )
          })}
        </div>
      )}

      <UserDetailModal userId={detailUserId} onClose={() => setDetailUserId(null)} />

      {/* Create user */}
      <ModalShell isOpen={creating} onClose={() => setCreating(false)} closeOnBackdrop={false} panelClassName="max-w-md" labelledById="user-create-title">
        <div className="p-6">
          <h3 id="user-create-title" className="text-lg font-semibold text-slate-900 dark:text-white">{t('users.createTitle')}</h3>
          <div className="mt-4 space-y-3">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">{t('users.username')}</label>
              <input type="text" value={newUsername} onChange={(e) => setNewUsername(e.target.value)} aria-label="new-username"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-700 dark:text-white" />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">{t('users.password')}</label>
              <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} aria-label="new-password"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-700 dark:text-white" />
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('users.passwordHint')}</p>
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">{t('users.role')}</label>
              <select value={newRoleId} onChange={(e) => setNewRoleId(e.target.value)} aria-label="new-user-role"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-700 dark:text-white">
                {roles.map((r) => <option key={r.id} value={r.id}>{roleLabel(r.name, tr)}</option>)}
              </select>
            </div>
          </div>
          {error && <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">{error}</p>}
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" onClick={() => setCreating(false)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {t('common:buttons.cancel')}
            </button>
            <button type="button" disabled={!newUsername || !newPassword || !newRoleId || createMutation.isPending}
              onClick={() => { setError(null); createMutation.mutate({ username: newUsername, password: newPassword, role_id: newRoleId }) }}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
              {t('common:buttons.create')}
            </button>
          </div>
        </div>
      </ModalShell>

      {/* Reset password */}
      <ModalShell isOpen={!!resetting} onClose={() => setResetting(null)} closeOnBackdrop={false} panelClassName="max-w-md" labelledById="user-reset-title">
        <div className="p-6">
          <h3 id="user-reset-title" className="text-lg font-semibold text-slate-900 dark:text-white">{t('users.resetTitle')}</h3>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{t('users.resetMessage', { username: resetting?.username ?? '' })}</p>
          <input type="password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} aria-label="reset-password"
            className="mt-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-600 dark:bg-slate-700 dark:text-white" />
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('users.resetHint')}</p>
          {error && <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">{error}</p>}
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" onClick={() => setResetting(null)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {t('common:buttons.cancel')}
            </button>
            <button type="button" disabled={!resetPassword || passwordMutation.isPending}
              onClick={() => resetting && passwordMutation.mutate({ id: resetting.id, password: resetPassword })}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
              {t('common:buttons.save')}
            </button>
          </div>
        </div>
      </ModalShell>

      {/* Delete user — the API token count is the part that silently breaks
          automation, so it is stated with the real number. (#222 D8) */}
      <ModalShell isOpen={!!deleting} onClose={() => setDeleting(null)} closeOnBackdrop={false} panelClassName="max-w-md" labelledById="user-delete-title">
        <div className="p-6">
          <h3 id="user-delete-title" className="text-lg font-semibold text-slate-900 dark:text-white">{t('users.deleteTitle')}</h3>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
            {t('users.deleteMessage', { username: deleting?.username ?? '' })}
          </p>
          {!!deleting?.api_token_count && (
            <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
              {t('users.deleteTokenWarning', { count: deleting.api_token_count })}
            </p>
          )}
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" onClick={() => setDeleting(null)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {t('common:buttons.cancel')}
            </button>
            <button type="button" onClick={() => deleting && deleteMutation.mutate(deleting.id)}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">
              {t('common:buttons.delete')}
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  )
}

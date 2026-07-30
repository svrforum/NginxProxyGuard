import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { createRole, deleteRole, fetchPermissionAreas, listRoles, updateRole } from '../../api/rbac'
import type { Role } from '../../types/rbac'
import { AddButton, EmptyState, EntityCard, IconButton, PencilIcon, TrashIcon } from '../common/listui'
import { ModalShell } from '../common/ModalShell'

/** Verbs a write grant implies, mirroring model.verbImplications on the server so
 *  the editor cannot save a role that 403s on its own list endpoint. */
const IMPLIED: Record<string, string[]> = {
  write: ['read'],
  delete: ['write', 'read'],
  create: ['read'],
  restore: ['read', 'create'],
}

/** Built-in role names are stable slugs; the label comes from i18n. */
function roleLabel(name: string, t: (k: string, o?: Record<string, unknown>) => string): string {
  if (name.startsWith('builtin.')) {
    return t(`roles.builtin.${name.slice('builtin.'.length)}`, { defaultValue: name })
  }
  return name
}

interface MatrixProps {
  areas: { Key: string; Verbs: string[] }[]
  selected: Set<string>
  readOnly: boolean
  onToggle: (permission: string, checked: boolean) => void
}

/** The area × verb grid. Rendered from the server's area table (not a hardcoded
 *  list) so a permission added server-side shows up without a UI change. */
function PermissionMatrix({ areas, selected, readOnly, onToggle }: MatrixProps) {
  const { t } = useTranslation('settings')
  const allVerbs = ['read', 'write', 'delete', 'create', 'restore']
  const usedVerbs = allVerbs.filter((v) => areas.some((a) => a.Verbs.includes(v)))

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 dark:border-slate-700">
            <th className="py-2 pr-4 text-left font-medium text-slate-500 dark:text-slate-400">
              {t('roles.area')}
            </th>
            {usedVerbs.map((v) => (
              <th key={v} className="px-3 py-2 text-center font-medium text-slate-500 dark:text-slate-400">
                {t(`roles.verbs.${v}`)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {areas.map((area) => (
            <tr key={area.Key} className="border-b border-slate-100 dark:border-slate-700/50">
              <td className="py-2 pr-4 text-slate-700 dark:text-slate-200">
                {t(`roles.areas.${area.Key}`, { defaultValue: area.Key })}
              </td>
              {usedVerbs.map((verb) => {
                const perm = `${area.Key}:${verb}`
                const supported = area.Verbs.includes(verb)
                return (
                  <td key={verb} className="px-3 py-2 text-center">
                    {supported ? (
                      <input
                        type="checkbox"
                        aria-label={perm}
                        checked={selected.has(perm)}
                        disabled={readOnly}
                        onChange={(e) => onToggle(perm, e.target.checked)}
                        className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 disabled:opacity-50 dark:border-slate-600"
                      />
                    ) : (
                      <span className="text-slate-300 dark:text-slate-600">–</span>
                    )}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function RoleManager() {
  const { t } = useTranslation(['settings', 'common'])
  // Narrow wrapper: roleLabel only needs (key, options) -> string, and i18next's
  // TFunction generic does not structurally match that signature.
  const tr = (k: string, o?: Record<string, unknown>) => String(t(k, o))
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<Role | null>(null)
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState<Role | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [error, setError] = useState<string | null>(null)

  const { data: areasData } = useQuery({ queryKey: ['permission-areas'], queryFn: fetchPermissionAreas })
  const { data, isLoading } = useQuery({ queryKey: ['roles'], queryFn: listRoles })
  const areas = useMemo(() => areasData?.areas ?? [], [areasData])

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['roles'] })
    // A role change can alter what the current user may see.
    queryClient.invalidateQueries({ queryKey: ['current-user'] })
  }

  const createMutation = useMutation({
    mutationFn: createRole,
    onSuccess: () => { invalidate(); closeForm() },
    onError: (e: Error) => setError(e.message),
  })
  const updateMutation = useMutation({
    mutationFn: ({ id, ...rest }: { id: string; name?: string; description?: string; permissions?: string[] }) =>
      updateRole(id, rest),
    onSuccess: () => { invalidate(); closeForm() },
    onError: (e: Error) => setError(e.message),
  })
  const deleteMutation = useMutation({
    mutationFn: deleteRole,
    onSuccess: () => { invalidate(); setDeleting(null) },
    onError: (e: Error) => { setError(e.message); setDeleting(null) },
  })

  function openCreate() {
    setCreating(true)
    setEditing(null)
    setName('')
    setDescription('')
    setSelected(new Set())
    setError(null)
  }

  function openEdit(role: Role) {
    setEditing(role)
    setCreating(false)
    setName(role.name)
    setDescription(role.description)
    setSelected(new Set(role.permissions ?? []))
    setError(null)
  }

  /** Duplicate: pre-fill from a built-in role, which is the only way to base a
   *  custom role on one since built-ins are immutable. */
  function openDuplicate(role: Role) {
    setCreating(true)
    setEditing(null)
    setName('')
    setDescription(role.description)
    setSelected(new Set(role.permissions ?? []))
    setError(null)
  }

  function closeForm() {
    setCreating(false)
    setEditing(null)
    setError(null)
  }

  function toggle(permission: string, checked: boolean) {
    const [area, verb] = permission.split(':')
    setSelected((prev) => {
      const next = new Set(prev)
      if (checked) {
        next.add(permission)
        // Grant the implied lesser verbs so the role is coherent.
        for (const lesser of IMPLIED[verb] ?? []) {
          if (areas.find((a) => a.Key === area)?.Verbs.includes(lesser)) {
            next.add(`${area}:${lesser}`)
          }
        }
      } else {
        next.delete(permission)
        // Removing read also removes what implied it, otherwise the saved role
        // would silently get read back from the server's verb hierarchy.
        if (verb === 'read') {
          for (const higher of ['write', 'delete', 'create', 'restore']) {
            next.delete(`${area}:${higher}`)
          }
        }
      }
      return next
    })
  }

  useEffect(() => {
    if (!creating && !editing) setError(null)
  }, [creating, editing])

  const formOpen = creating || !!editing
  const readOnlyForm = !!editing?.is_builtin

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('roles.title')}</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">{t('roles.subtitle')}</p>
        </div>
        <AddButton onClick={openCreate}>{t('roles.add')}</AddButton>
      </div>

      {error && !formOpen && (
        <div className="mb-3 rounded-lg bg-red-50 px-4 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
          {error}
        </div>
      )}

      {isLoading ? (
        <p className="text-sm text-slate-500">{t('common:loading', { defaultValue: 'Loading…' })}</p>
      ) : !data?.data?.length ? (
        <EmptyState>{t('roles.empty')}</EmptyState>
      ) : (
        <div className="space-y-3" data-testid="role-list">
          {data.data.map((role) => (
            <EntityCard key={role.id}>
              <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-semibold text-slate-900 dark:text-white">
                      {roleLabel(role.name, tr)}
                    </span>
                    {role.is_superuser && (
                      <span className="inline-flex items-center rounded-md bg-amber-50 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
                        {t('roles.superuser')}
                      </span>
                    )}
                    {role.is_builtin && (
                      <span className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:bg-slate-700/50 dark:text-slate-400">
                        {t('roles.builtinBadge')}
                      </span>
                    )}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-slate-500 dark:text-slate-400">
                    <span>{role.description}</span>
                    <span className="text-slate-300 dark:text-slate-600">·</span>
                    <span>
                      {role.is_superuser
                        ? t('roles.allPermissions')
                        : t('roles.permissionCount', { count: role.permissions?.length ?? 0 })}
                    </span>
                    <span className="text-slate-300 dark:text-slate-600">·</span>
                    <span>{t('roles.userCount', { count: role.user_count })}</span>
                  </div>
                </div>
                <div className="flex items-center gap-0.5">
                  <IconButton onClick={() => openEdit(role)} title={role.is_builtin ? t('roles.viewOnly') : t('common:buttons.edit')}>
                    <PencilIcon />
                  </IconButton>
                  <IconButton onClick={() => openDuplicate(role)} title={t('roles.duplicate')}>
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                  </IconButton>
                  <IconButton
                    onClick={() => setDeleting(role)}
                    disabled={role.is_builtin}
                    title={role.is_builtin ? t('roles.builtinLocked') : t('common:buttons.delete')}
                    variant="danger"
                  >
                    <TrashIcon />
                  </IconButton>
                </div>
              </div>
            </EntityCard>
          ))}
        </div>
      )}

      {/* Role editor */}
      <ModalShell isOpen={formOpen} onClose={closeForm} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="role-form-title">
        <div className="p-6">
          <h3 id="role-form-title" className="text-lg font-semibold text-slate-900 dark:text-white">
            {editing ? (readOnlyForm ? t('roles.viewTitle') : t('roles.editTitle')) : t('roles.createTitle')}
          </h3>

          {readOnlyForm && (
            <p className="mt-2 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600 dark:bg-slate-700/50 dark:text-slate-300">
              {t('roles.builtinHint')}
            </p>
          )}

          <div className="mt-4 space-y-3">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">
                {t('roles.name')}
              </label>
              <input
                type="text"
                value={readOnlyForm ? roleLabel(name, tr) : name}
                onChange={(e) => setName(e.target.value)}
                disabled={readOnlyForm}
                aria-label="role-name"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm disabled:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-white dark:disabled:bg-slate-800"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">
                {t('roles.description')}
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                disabled={readOnlyForm}
                aria-label="role-description"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm disabled:bg-slate-50 dark:border-slate-600 dark:bg-slate-700 dark:text-white dark:disabled:bg-slate-800"
              />
            </div>
          </div>

          <div className="mt-5">
            {editing?.is_superuser ? (
              <p className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
                {t('roles.superuserHint')}
              </p>
            ) : (
              <PermissionMatrix areas={areas} selected={selected} readOnly={readOnlyForm} onToggle={toggle} />
            )}
          </div>

          {error && (
            <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
              {error}
            </p>
          )}

          <div className="mt-6 flex justify-end gap-2">
            <button
              type="button"
              onClick={closeForm}
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700"
            >
              {readOnlyForm ? t('common:buttons.close') : t('common:buttons.cancel')}
            </button>
            {!readOnlyForm && (
              <button
                type="button"
                onClick={() => {
                  setError(null)
                  const permissions = Array.from(selected)
                  if (editing) {
                    updateMutation.mutate({ id: editing.id, name, description, permissions })
                  } else {
                    createMutation.mutate({ name, description, permissions })
                  }
                }}
                disabled={!name.trim() || createMutation.isPending || updateMutation.isPending}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 disabled:opacity-50"
              >
                {t('common:buttons.save')}
              </button>
            )}
          </div>
        </div>
      </ModalShell>

      {/* Delete confirmation */}
      <ModalShell isOpen={!!deleting} onClose={() => setDeleting(null)} closeOnBackdrop={false} panelClassName="max-w-md" labelledById="role-delete-title">
        <div className="p-6">
          <h3 id="role-delete-title" className="text-lg font-semibold text-slate-900 dark:text-white">
            {t('roles.deleteTitle')}
          </h3>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
            {t('roles.deleteMessage', { name: deleting ? roleLabel(deleting.name, tr) : '' })}
          </p>
          {!!deleting?.user_count && (
            <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
              {t('roles.deleteBlocked', { count: deleting.user_count })}
            </p>
          )}
          <div className="mt-6 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setDeleting(null)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700"
            >
              {t('common:buttons.cancel')}
            </button>
            <button
              type="button"
              onClick={() => deleting && deleteMutation.mutate(deleting.id)}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700"
            >
              {t('common:buttons.delete')}
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  )
}

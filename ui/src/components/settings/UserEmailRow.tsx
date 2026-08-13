import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { setUserEmail } from '../../api/rbac'

/** Addresses NPG makes up for accounts that were never given one. They keep the
 *  column populated but can never match an identity provider, so the row says
 *  so rather than presenting them as a working address.
 *
 *  Two forms exist: `<username>@localhost`, which the current seed and every
 *  admin-created account without an address get, and `admin@nginx-guard.local`,
 *  which older installs were seeded with. (#240) */
function isPlaceholder(email: string): boolean {
  return email.endsWith('@localhost') || email === 'admin@nginx-guard.local'
}

/**
 * The address SSO links this account by, with an inline edit.
 *
 * Editing is admin-only on the server, deliberately: SSO matches a verified
 * provider email to a local account and then syncs the role from the provider's
 * groups, so a user able to set their own address could claim an
 * administrator's before that administrator first signs in.
 */
export function UserEmailRow({ userId, email }: { userId: string; email: string }) {
  const { t } = useTranslation(['settings', 'common'])
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(email)
  const [error, setError] = useState('')

  const save = useMutation({
    mutationFn: () => setUserEmail(userId, value.trim()),
    onSuccess: () => {
      setEditing(false)
      setError('')
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
    },
    onError: (e: unknown) => setError(e instanceof Error ? e.message : t('users.emailSaveFailed')),
  })

  if (editing) {
    return (
      <div className="py-2">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="email"
            value={value}
            autoFocus
            onChange={(e) => setValue(e.target.value)}
            className="min-w-0 flex-1 px-3 py-1.5 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            placeholder={t('users.emailPlaceholder')}
          />
          <button
            onClick={() => save.mutate()}
            disabled={save.isPending || !value.trim() || value.trim() === email}
            className="px-3 py-1.5 text-sm bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
          >
            {t('common:buttons.save')}
          </button>
          <button
            onClick={() => {
              setEditing(false)
              setValue(email)
              setError('')
            }}
            className="px-3 py-1.5 text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg"
          >
            {t('common:buttons.cancel')}
          </button>
        </div>
        {error && <p className="mt-1.5 text-xs text-red-600 dark:text-red-400">{error}</p>}
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between gap-2 py-2">
      <span className="text-sm text-slate-500 dark:text-slate-400">{t('users.email')}</span>
      <span className="flex min-w-0 items-center gap-2">
        <span className="truncate font-mono text-xs text-slate-900 dark:text-slate-100" title={email}>
          {email || '—'}
        </span>
        {isPlaceholder(email) && (
          <span
            className="shrink-0 rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
            title={t('users.emailPlaceholderHint')}
          >
            {t('users.emailPlaceholderBadge')}
          </span>
        )}
        <button
          onClick={() => setEditing(true)}
          className="shrink-0 text-xs text-primary-600 hover:underline dark:text-primary-400"
        >
          {t('common:buttons.edit')}
        </button>
      </span>
    </div>
  )
}

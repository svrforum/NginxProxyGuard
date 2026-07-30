import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { changePassword, logout, User } from '../api/auth'

interface ForcePasswordChangeProps {
  user: User
  onComplete: () => void
}

/**
 * Shown when an administrator created this account and it has not picked its own
 * password yet (#222).
 *
 * The server blocks every endpoint except this one until the change lands, so
 * without this screen the account would see an app where nothing works. Distinct
 * from InitialSetup, which also forces a username change — right for the seeded
 * admin/admin account, wrong for a name an administrator just chose.
 */
export function ForcePasswordChange({ user, onComplete }: ForcePasswordChangeProps) {
  const { t } = useTranslation(['auth', 'common'])
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (next !== confirm) {
      setError(t('forcePasswordChange.mismatch'))
      return
    }
    setSaving(true)
    try {
      await changePassword({
        current_password: current,
        new_password: next,
        new_password_confirm: confirm,
      })
      onComplete()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('forcePasswordChange.failed'))
    } finally {
      setSaving(false)
    }
  }

  const abandon = async () => {
    await logout()
    window.location.reload()
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-900">
      <div className="w-full max-w-md rounded-xl bg-white p-8 shadow-lg dark:bg-slate-800">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t('forcePasswordChange.title')}
        </h1>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
          {t('forcePasswordChange.message', { username: user.username })}
        </p>

        <form onSubmit={submit} className="mt-6 space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {t('forcePasswordChange.current')}
            </label>
            <input
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              aria-label="current-password"
              className="w-full rounded-lg border border-slate-300 px-3 py-2.5 text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-white"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {t('forcePasswordChange.new')}
            </label>
            <input
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              aria-label="new-password"
              className="w-full rounded-lg border border-slate-300 px-3 py-2.5 text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-white"
            />
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              {t('forcePasswordChange.hint')}
            </p>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">
              {t('forcePasswordChange.confirm')}
            </label>
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              aria-label="confirm-password"
              className="w-full rounded-lg border border-slate-300 px-3 py-2.5 text-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-white"
            />
          </div>

          {error && (
            <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={!current || !next || !confirm || saving}
            className="w-full rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-indigo-700 disabled:opacity-50"
          >
            {saving ? t('common:buttons.save') : t('forcePasswordChange.submit')}
          </button>
        </form>

        <button
          type="button"
          onClick={abandon}
          className="mt-4 w-full text-center text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
        >
          {t('forcePasswordChange.logout')}
        </button>
      </div>
    </div>
  )
}

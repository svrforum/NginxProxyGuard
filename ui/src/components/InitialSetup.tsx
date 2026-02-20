import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { changeCredentials, User } from '../api/auth'
import { LanguageSwitcher } from './LanguageSwitcher'

interface InitialSetupProps {
  user: User
  onComplete: () => void
}

export function InitialSetup({ user, onComplete }: InitialSetupProps) {
  const { t } = useTranslation(['auth', 'common'])
  const [currentPassword, setCurrentPassword] = useState('')
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    // Validation
    if (newUsername.length < 3) {
      setError(t('initialSetup.usernameMinLength'))
      return
    }

    if (newPassword.length < 10) {
      setError(t('initialSetup.passwordMinLength'))
      return
    }

    if (newPassword !== confirmPassword) {
      setError(t('initialSetup.passwordMismatch'))
      return
    }

    // Check if username is same as default
    if (newUsername.toLowerCase() === 'admin') {
      setError(t('initialSetup.changeDefaultUsername'))
      return
    }

    setLoading(true)

    try {
      await changeCredentials({
        current_password: currentPassword,
        new_username: newUsername,
        new_password: newPassword,
        new_password_confirm: confirmPassword
      })
      onComplete()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToChangeCredentials'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="w-full max-w-md">
        {/* Logo/Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-amber-500 rounded-2xl mb-4">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold text-white">{t('initialSetup.title')}</h1>
          <p className="text-slate-400 mt-2">
            {t('initialSetup.subtitle')}
          </p>
        </div>

        {/* Setup Form */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <p className="font-medium text-amber-800">{t('initialSetup.securityNotice')}</p>
                <p className="text-sm text-amber-700 mt-1">
                  {t('initialSetup.loggedInAs', { username: user.username }).split('<code>').map((part, i) =>
                    i === 0 ? part : (
                      <span key={i}>
                        <code className="bg-amber-100 px-1 rounded">{part.split('</code>')[0]}</code>
                        {part.split('</code>')[1]}
                      </span>
                    )
                  )}
                </p>
              </div>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                {error}
              </div>
            )}

            <div>
              <label htmlFor="currentPassword" className="block text-sm font-medium text-slate-700 mb-1.5">
                {t('initialSetup.currentPassword')}
              </label>
              <input
                type="password"
                id="currentPassword"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                placeholder={t('initialSetup.currentPasswordPlaceholder')}
                required
              />
              <p className="text-xs text-slate-500 mt-1">{t('initialSetup.defaultPasswordHint')}</p>
            </div>

            <div className="border-t pt-5">
              <h3 className="text-sm font-medium text-slate-900 mb-4">{t('initialSetup.newCredentials')}</h3>

              <div className="space-y-4">
                <div>
                  <label htmlFor="newUsername" className="block text-sm font-medium text-slate-700 mb-1.5">
                    {t('initialSetup.newUsername')}
                  </label>
                  <input
                    type="text"
                    id="newUsername"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                    placeholder={t('initialSetup.newUsernamePlaceholder')}
                    required
                    minLength={3}
                  />
                </div>

                <div>
                  <label htmlFor="newPassword" className="block text-sm font-medium text-slate-700 mb-1.5">
                    {t('initialSetup.newPassword')}
                  </label>
                  <input
                    type="password"
                    id="newPassword"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                    placeholder={t('initialSetup.newPasswordPlaceholder')}
                    required
                    minLength={8}
                  />
                </div>

                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-slate-700 mb-1.5">
                    {t('initialSetup.confirmPassword')}
                  </label>
                  <input
                    type="password"
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                    placeholder={t('initialSetup.confirmPasswordPlaceholder')}
                    required
                  />
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-primary-600 text-white py-2.5 px-4 rounded-lg font-medium hover:bg-primary-700 focus:ring-4 focus:ring-primary-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  {t('initialSetup.submitting')}
                </span>
              ) : (
                t('initialSetup.submit')
              )}
            </button>
          </form>
        </div>

        {/* Footer with Language Switcher */}
        <div className="flex items-center justify-center gap-4 mt-6">
          <p className="text-slate-500 text-sm">
            {t('initialSetup.footer')}
          </p>
          <span className="text-slate-600">|</span>
          <LanguageSwitcher variant="dropdown" className="text-slate-400" />
        </div>
      </div>
    </div>
  )
}

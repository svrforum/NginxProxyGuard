import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { login, verify2FA } from '../api/auth'
import { LanguageSwitcher } from './LanguageSwitcher'

interface LoginProps {
  onLogin: () => void
}

export function Login({ onLogin }: LoginProps) {
  const { t } = useTranslation(['auth', 'common'])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [tempToken, setTempToken] = useState('')
  const [requires2FA, setRequires2FA] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const response = await login({ username, password })

      if (response.requires_2fa && response.temp_token) {
        setTempToken(response.temp_token)
        setRequires2FA(true)
      } else if (response.token) {
        onLogin()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.networkError'))
    } finally {
      setLoading(false)
    }
  }

  const handle2FASubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await verify2FA({ temp_token: tempToken, totp_code: totpCode })
      onLogin()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.networkError'))
    } finally {
      setLoading(false)
    }
  }

  const handleBackToLogin = () => {
    setRequires2FA(false)
    setTempToken('')
    setTotpCode('')
    setError('')
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="w-full max-w-md">
        {/* Logo/Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center mb-4">
            <img src="/favicon.ico" alt="NPG Logo" className="w-20 h-20 rounded-2xl" />
          </div>
          <h1 className="text-3xl font-bold text-white">Nginx Proxy Guard</h1>
          <p className="text-slate-400 mt-2">Secure Reverse Proxy Manager by Svrforum</p>
        </div>

        {/* Login Form */}
        <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-2xl p-8">
          {!requires2FA ? (
            <>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-6 text-center">
                {t('login.title')}
              </h2>

              <form onSubmit={handleSubmit} className="space-y-5">
                {error && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded-lg text-sm">
                    {error}
                  </div>
                )}

                <div>
                  <label htmlFor="username" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    {t('login.email')}
                  </label>
                  <input
                    type="text"
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                    placeholder={t('login.emailPlaceholder')}
                    required
                    autoFocus
                  />
                </div>

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                    {t('login.password')}
                  </label>
                  <input
                    type="password"
                    id="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                    placeholder={t('login.passwordPlaceholder')}
                    required
                  />
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
                      {t('login.submitting')}
                    </span>
                  ) : (
                    t('login.submit')
                  )}
                </button>
              </form>
            </>
          ) : (
            <>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-2 text-center">
                {t('changePassword.title', { defaultValue: 'Two-Factor Authentication' })}
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-sm text-center mb-6">
                {t('common:validation.required', { defaultValue: 'Enter the 6-digit code from your authenticator app' })}
              </p>

              <form onSubmit={handle2FASubmit} className="space-y-5">
                {error && (
                  <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded-lg text-sm">
                    {error}
                  </div>
                )}

                <div>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="w-full px-4 py-4 border border-slate-300 dark:border-slate-600 rounded-lg text-center text-3xl tracking-[0.5em] font-mono focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                    placeholder="000000"
                    maxLength={6}
                    required
                    autoFocus
                  />
                  <p className="text-slate-500 dark:text-slate-400 text-xs text-center mt-2">
                    {t('common:messages.noData', { defaultValue: 'You can also use a backup code' })}
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={loading || totpCode.length < 6}
                  className="w-full bg-primary-600 text-white py-2.5 px-4 rounded-lg font-medium hover:bg-primary-700 focus:ring-4 focus:ring-primary-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      {t('common:status.processing')}
                    </span>
                  ) : (
                    t('common:buttons.confirm')
                  )}
                </button>

                <button
                  type="button"
                  onClick={handleBackToLogin}
                  className="w-full text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white py-2 text-sm transition-colors"
                >
                  {t('common:buttons.back')}
                </button>
              </form>
            </>
          )}
        </div>

        {/* Footer with Language Switcher */}
        <div className="flex items-center justify-center gap-4 mt-6">
          <p className="text-slate-500 text-sm">
            Protected by Nginx Proxy Guard Security
          </p>
          <span className="text-slate-600">|</span>
          <LanguageSwitcher variant="dropdown" className="text-slate-400" />
        </div>
      </div>
    </div>
  )
}

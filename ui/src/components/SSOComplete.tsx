import { useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { setToken } from '../api/auth'

interface SSOCompleteProps {
  /** Re-runs the app's auth check once the token is stored. */
  onAuthenticated: () => void
}

/**
 * Landing point of the OIDC callback (#227).
 *
 * The session token arrives in the URL FRAGMENT rather than the query string:
 * browsers never send a fragment to a server, so the token cannot appear in an
 * access log, a Referer header, or a reverse proxy's request line. This
 * component reads it, stores it exactly where the password login stores its
 * token, and scrubs the address bar before anything else renders.
 */
export function SSOComplete({ onAuthenticated }: SSOCompleteProps) {
  const { t } = useTranslation('auth')
  // React 19 runs effects twice in development; the fragment is gone the second
  // time, which would look like a failure.
  const handled = useRef(false)

  useEffect(() => {
    if (handled.current) return
    handled.current = true

    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const token = params.get('token')
    const error = params.get('error')

    if (token) {
      setToken(token)
      // Drop the fragment before handing control back, so a reload or a shared
      // URL cannot carry the token anywhere.
      window.history.replaceState(null, '', '/')
      onAuthenticated()
      return
    }
    // Send the failure back to the login screen, which knows how to render it.
    window.location.replace('/' + (error ? '#error=' + encodeURIComponent(error) : ''))
  }, [onAuthenticated])

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="text-center text-slate-300">
        <svg className="animate-spin w-8 h-8 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        {t('login.ssoCompleting')}
      </div>
    </div>
  )
}

export default SSOComplete

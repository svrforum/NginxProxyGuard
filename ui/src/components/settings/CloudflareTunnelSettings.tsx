import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../common/HelpTip'
import {
  fetchCloudflareTunnel,
  updateCloudflareTunnel,
  fetchTunnelStatus,
} from '../../api/cloudflare-tunnel'
import type { TunnelStatus, UpdateCloudflareTunnelRequest } from '../../types/cloudflare-tunnel'

const badgeClasses: Record<TunnelStatus['state'], string> = {
  disabled: 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300',
  starting: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400',
  connected: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
  error: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
}

const dotClasses: Record<TunnelStatus['state'], string> = {
  disabled: 'bg-slate-400',
  starting: 'bg-amber-500',
  connected: 'bg-green-500',
  error: 'bg-red-500',
}

// The Cloudflare dashboard shows the connector token embedded in a full
// install command (`sudo cloudflared service install eyJhFAKE...` or
// `docker run ... --token eyJhFAKE...`), and users paste the whole command.
// Extract the longest base64url blob starting with "eyJ" (the base64 of the
// token's {"a":... JSON header). If nothing matches, return the trimmed input
// unchanged so bare tokens and invalid input still flow to server-side
// validation.
export function extractTunnelToken(input: string): string {
  const trimmed = input.trim()
  const matches = trimmed.match(/eyJ[A-Za-z0-9_=-]{30,}/g)
  if (!matches) return trimmed
  return matches.reduce((longest, m) => (m.length > longest.length ? m : longest))
}

export default function CloudflareTunnelSettings() {
  const { t } = useTranslation('settings')
  const queryClient = useQueryClient()

  // Local edits: null/'' = untouched, fall back to server state.
  const [enabledEdit, setEnabledEdit] = useState<boolean | null>(null)
  const [tokenInput, setTokenInput] = useState('')
  const [replacingToken, setReplacingToken] = useState(false)
  const [guideOpen, setGuideOpen] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const { data: settings, isLoading } = useQuery({
    queryKey: ['cloudflare-tunnel'],
    queryFn: fetchCloudflareTunnel,
  })

  // Poll the connector status only while the tunnel is enabled server-side.
  const { data: status } = useQuery({
    queryKey: ['cloudflare-tunnel-status'],
    queryFn: fetchTunnelStatus,
    refetchInterval: 15000,
    enabled: settings?.enabled === true,
  })

  const updateMutation = useMutation({
    mutationFn: updateCloudflareTunnel,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloudflare-tunnel'] })
      queryClient.invalidateQueries({ queryKey: ['cloudflare-tunnel-status'] })
      setEnabledEdit(null)
      setTokenInput('')
      setReplacingToken(false)
      setSaveMessage({ type: 'success', text: t('messages.saveSuccess') })
      setTimeout(() => setSaveMessage(null), 3000)
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${error.message}` })
      setTimeout(() => setSaveMessage(null), 5000)
    },
  })

  const effEnabled = enabledEdit ?? settings?.enabled ?? false
  const typedToken = tokenInput.trim()
  const hasChanges =
    (enabledEdit !== null && enabledEdit !== settings?.enabled) || typedToken !== ''

  const handleSave = () => {
    if (!hasChanges || updateMutation.isPending) return
    const payload: UpdateCloudflareTunnelRequest = {}
    if (enabledEdit !== null && enabledEdit !== settings?.enabled) {
      payload.enabled = enabledEdit
    }
    // The masked value must never round-trip — only send a token the user
    // actually typed; omitting it keeps the stored one. Extract defensively
    // here too, even though the input is already normalized on change.
    if (typedToken !== '') {
      payload.token = extractTunnelToken(typedToken)
    }
    updateMutation.mutate(payload)
  }

  // Badge state: server-side disabled needs no probe; while enabled, trust the
  // status endpoint (right after enabling, it reports "starting" anyway).
  const badgeState: TunnelStatus['state'] = !settings?.enabled
    ? 'disabled'
    : (status?.state ?? 'starting')
  const badgeLabel =
    badgeState === 'connected'
      ? `${t('cloudflareTunnel.status.connected')} (${status?.connections ?? 0})`
      : t(`cloudflareTunnel.status.${badgeState}`)

  const showTokenInput = !settings?.has_token || replacingToken

  // Origin service URL for the CF dashboard's Public Hostname — reflects the
  // actual NGINX_HTTPS_PORT (e.g. https://localhost:8443), not a hardcoded 443.
  const originUrl = settings?.origin_service_url || 'https://localhost:443'
  // http:// variant (NGINX_HTTP_PORT) for hosts served over plain HTTP.
  const originUrlHttp = settings?.origin_service_url_http || 'http://localhost:80'

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header + Save */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-800 dark:text-white flex items-center gap-3">
            {t('cloudflareTunnel.title')}
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${badgeClasses[badgeState]}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${dotClasses[badgeState]}`} />
              {badgeLabel}
            </span>
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('cloudflareTunnel.description')}
          </p>
        </div>
        {hasChanges && (
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 text-sm font-medium flex items-center gap-2"
          >
            {updateMutation.isPending ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                {t('cloudflareTunnel.saving')}
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                {t('cloudflareTunnel.save')}
              </>
            )}
          </button>
        )}
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-900/30'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/30'
          }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Enable Toggle + Token Card */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              {t('cloudflareTunnel.enable')}
              <HelpTip contentKey="help.cloudflareTunnel.enable" ns="settings" />
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {t('cloudflareTunnel.enableDescription')}
            </p>
          </div>
          <button
            onClick={() => setEnabledEdit(!effEnabled)}
            role="switch"
            aria-checked={effEnabled}
            aria-label={t('cloudflareTunnel.enable')}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              effEnabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
              effEnabled ? 'translate-x-6' : 'translate-x-1'
            }`} />
          </button>
        </div>

        <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
          <label className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
            {t('cloudflareTunnel.token')}
            <HelpTip contentKey="help.cloudflareTunnel.token" ns="settings" />
          </label>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
            {t('cloudflareTunnel.tokenDescription')}
          </p>
          {showTokenInput ? (
            <>
              <div className="flex items-center gap-2">
                <input
                  type="password"
                  value={tokenInput}
                  onChange={(e) => setTokenInput(extractTunnelToken(e.target.value))}
                  autoComplete="off"
                  placeholder={t('cloudflareTunnel.tokenPlaceholder')}
                  className="flex-1 px-4 py-2.5 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-700 dark:text-slate-300 font-mono placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-colors"
                />
                {settings?.has_token && (
                  <button
                    onClick={() => { setReplacingToken(false); setTokenInput('') }}
                    className="px-3 py-2 text-sm text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    {t('cloudflareTunnel.cancelReplace')}
                  </button>
                )}
              </div>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-1.5">
                {t('cloudflareTunnel.tokenPasteHint')}
              </p>
            </>
          ) : (
            <div className="flex items-center gap-2">
              <div className="flex-1 px-4 py-2.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-500 dark:text-slate-400 font-mono">
                {settings?.token_masked}
              </div>
              <button
                onClick={() => setReplacingToken(true)}
                className="px-3 py-2 text-sm font-medium text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg transition-colors"
              >
                {t('cloudflareTunnel.replaceToken')}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Setup Guide Accordion */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
        <button
          onClick={() => setGuideOpen(!guideOpen)}
          className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors"
        >
          <span className="text-sm font-semibold text-slate-800 dark:text-white flex items-center gap-2">
            <svg className="w-5 h-5 text-primary-600 dark:text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
            </svg>
            {t('cloudflareTunnel.guide.title')}
          </span>
          <svg className={`w-5 h-5 text-slate-400 transition-transform ${guideOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {guideOpen && (
          <div className="px-6 pb-6 border-t border-slate-200 dark:border-slate-700">
            <ol className="mt-4 space-y-4">
              {([1, 2, 3, 4, 5] as const).map((n) => (
                <li key={n} className="flex gap-3">
                  <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 text-xs font-bold flex items-center justify-center mt-0.5">
                    {n}
                  </span>
                  <div className="text-sm text-slate-600 dark:text-slate-300">
                    <p>{t(`cloudflareTunnel.guide.step${n}`, { originUrl })}</p>
                    {n === 4 && (
                      <div className="mt-2 space-y-2">
                        <div className="p-3 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg">
                          <p className="text-xs text-amber-700 dark:text-amber-400">
                            {t('cloudflareTunnel.guide.redirectLoopWarning', { originUrl })}
                          </p>
                        </div>
                        <div className="p-3 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg">
                          <p className="text-xs text-amber-700 dark:text-amber-400">
                            {t('cloudflareTunnel.guide.wildcardPriorityWarning')}
                          </p>
                        </div>
                        <div className="p-3 bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg">
                          <p className="text-xs text-blue-700 dark:text-blue-400">
                            {t('cloudflareTunnel.guide.httpOnlyNote', { originUrlHttp })}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getSystemSettings, updateSystemSettings } from '../../api/settings'
import { HelpTip } from '../common/HelpTip'

const REAL_IP_HEADERS = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP']

/**
 * Trusted proxies decide whose forwarded-client-address header nginx believes.
 * Everything that judges a visitor by address — GeoIP country rules, access
 * lists, banned IPs, fail2ban, rate limiting, the WAF — reads the result, which
 * is why the screen leads with what happens if the list is wrong rather than
 * burying it in a tooltip.
 */
export default function TrustedProxySettings() {
  const { t } = useTranslation(['settings', 'common'])
  const queryClient = useQueryClient()

  const { data: settings, isLoading } = useQuery({
    queryKey: ['system-settings'],
    queryFn: getSystemSettings,
  })

  const [preset, setPreset] = useState('none')
  const [header, setHeader] = useState('X-Forwarded-For')
  const [cidrs, setCidrs] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    if (!settings) return
    setPreset(settings.trusted_proxy_preset || 'none')
    setHeader(settings.real_ip_header || 'X-Forwarded-For')
    setCidrs(settings.trusted_proxy_cidrs || '')
  }, [settings])

  const mutation = useMutation({
    mutationFn: () =>
      updateSystemSettings({
        trusted_proxy_preset: preset,
        real_ip_header: header,
        trusted_proxy_cidrs: cidrs,
      }),
    onSuccess: () => {
      setError(null)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
      queryClient.invalidateQueries({ queryKey: ['system-settings'] })
    },
    onError: (e: unknown) => {
      setSaved(false)
      setError(e instanceof Error ? e.message : String(e))
    },
  })

  if (isLoading) {
    return <div className="text-slate-500 dark:text-slate-400">{t('common:status.loading')}</div>
  }

  const builtins: string[] = settings?.trusted_proxy_builtins || []
  const presetRanges: string[] = settings?.trusted_proxy_preset_ranges || []
  const cfUpdated = settings?.cloudflare_ranges_updated

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-slate-800 dark:text-slate-100 mb-1">
          {t('trustedProxies.title')}
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('trustedProxies.intro')}</p>

        <div className="mt-4 p-4 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20">
          <p className="text-sm text-amber-800 dark:text-amber-200">{t('trustedProxies.safetyWarning')}</p>
        </div>
      </div>

      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6 space-y-5">
        {/* Preset */}
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
            {t('trustedProxies.preset')}
            <HelpTip content={t('trustedProxies.presetHelp')} />
          </label>
          <select
            value={preset}
            onChange={(e) => setPreset(e.target.value)}
            className="w-full md:w-80 px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
          >
            <option value="none">{t('trustedProxies.presetNone')}</option>
            <option value="cloudflare">{t('trustedProxies.presetCloudflare')}</option>
          </select>
          {preset === 'cloudflare' && (
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t('trustedProxies.cloudflareRanges', { count: presetRanges.length, date: cfUpdated })}
            </p>
          )}
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('trustedProxies.tunnelNote')}</p>
        </div>

        {/* Header */}
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
            {t('trustedProxies.header')}
            <HelpTip content={t('trustedProxies.headerHelp')} />
          </label>
          <select
            value={header}
            onChange={(e) => setHeader(e.target.value)}
            className="w-full md:w-80 px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
          >
            {REAL_IP_HEADERS.map((h) => (
              <option key={h} value={h}>
                {h}
                {h === 'X-Forwarded-For' ? ` — ${t('trustedProxies.headerDefaultSuffix')}` : ''}
              </option>
            ))}
          </select>
          {header !== 'X-Forwarded-For' && (
            <div className="mt-2 p-3 rounded-lg border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20">
              <p className="text-xs text-red-700 dark:text-red-300">{t('trustedProxies.headerSwitchWarning')}</p>
            </div>
          )}
        </div>

        {/* Custom CIDRs */}
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
            {t('trustedProxies.custom')}
            <HelpTip content={t('trustedProxies.customHelp')} />
          </label>
          <textarea
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            rows={5}
            spellCheck={false}
            placeholder={t('trustedProxies.customPlaceholder')}
            className="w-full px-4 py-2.5 font-mono text-sm border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
          />
        </div>

        {/* Built-ins, read-only */}
        <div>
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            {t('trustedProxies.builtins')}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('trustedProxies.builtinsHelp')}</p>
          <div className="flex flex-wrap gap-1">
            {builtins.map((b) => (
              <span
                key={b}
                className="px-2 py-0.5 rounded text-xs font-mono bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"
              >
                {b}
              </span>
            ))}
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-lg border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20">
            <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="px-4 py-2 rounded-lg font-medium bg-primary-600 hover:bg-primary-700 text-white transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? t('common:status.saving') : t('common:buttons.save')}
          </button>
          {saved && (
            <span className="text-sm text-green-600 dark:text-green-400">{t('trustedProxies.savedApplying')}</span>
          )}
        </div>
      </div>
    </div>
  )
}

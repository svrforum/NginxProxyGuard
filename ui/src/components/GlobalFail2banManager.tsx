import { useState, useEffect, useId, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getGlobalFail2ban, updateGlobalFail2ban } from '../api/global-fail2ban'
import { HelpTip } from './common/HelpTip'
import { BAN_DURATIONS, CUSTOM_DURATION, isCustomDuration } from './banned-ip/banDurations'

/**
 * The global jail acts on requests that matched no configured host — the
 * catch-all traffic a per-host jail can never see, which is why adding 444 to a
 * host's fail codes does nothing.
 *
 * Its bans apply to EVERY host, so the screen leads with that rather than
 * burying it: a false positive here is an instance-wide outage, not one site's
 * problem. The server enforces the same thing by refusing to switch the jail on
 * while Trusted Proxies are empty, unless the operator confirms that nothing
 * sits in front of NPG (#400).
 */
export function GlobalFail2banManager() {
  const { t } = useTranslation(['fail2ban', 'common', 'waf'])
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['global-fail2ban'],
    queryFn: getGlobalFail2ban,
  })

  const [enabled, setEnabled] = useState(false)
  const [maxRetries, setMaxRetries] = useState(5)
  const [findTime, setFindTime] = useState(600)
  const [banTime, setBanTime] = useState(3600)
  const [failCodes, setFailCodes] = useState('400,444')
  const [action, setAction] = useState('log')
  const [ignorePrivate, setIgnorePrivate] = useState(false)
  const [confirmNoProxy, setConfirmNoProxy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const confirmId = useId()
  const errorId = useId()
  const confirmRef = useRef<HTMLInputElement>(null)

  // Only switching the jail on is checked, so an enabled jail never asks again.
  const needsConfirm = !!data && !data.enabled && enabled && !data.trusted_proxies_configured
  const confirmMissing = needsConfirm && !confirmNoProxy

  useEffect(() => {
    if (!data) return
    setEnabled(data.enabled)
    setMaxRetries(data.max_retries)
    setFindTime(data.find_time)
    setBanTime(data.ban_time)
    setFailCodes(data.fail_codes)
    setAction(data.action)
    setIgnorePrivate(data.ignore_private_ips ?? false)
  }, [data])

  const mutation = useMutation({
    mutationFn: () =>
      updateGlobalFail2ban({
        enabled,
        max_retries: maxRetries,
        find_time: findTime,
        ban_time: banTime,
        fail_codes: failCodes,
        action,
        ignore_private_ips: ignorePrivate,
        confirm_no_proxy: needsConfirm ? confirmNoProxy : undefined,
      }),
    onSuccess: () => {
      setError(null)
      setConfirmNoProxy(false)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
      queryClient.invalidateQueries({ queryKey: ['global-fail2ban'] })
    },
    onError: (e: unknown) => {
      setSaved(false)
      setError(e instanceof Error ? e.message : String(e))
    },
  })

  const save = () => {
    if (confirmMissing) {
      setSaved(false)
      setError(t('global.confirmNoProxyRequired'))
      confirmRef.current?.focus()
      return
    }
    mutation.mutate()
  }

  if (isLoading) {
    return <div className="text-slate-500 dark:text-slate-400">{t('common:status.loading')}</div>
  }

  const customBanTime = isCustomDuration(banTime)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">{t('global.title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('global.subtitle')}</p>
      </div>

      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6 space-y-5">
        <p className="text-sm text-slate-600 dark:text-slate-400">{t('global.intro')}</p>

        <div className="p-4 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20">
          <p className="text-sm text-amber-800 dark:text-amber-200">{t('global.blastRadius')}</p>
        </div>

        <p className="text-xs text-slate-500 dark:text-slate-400">{t('global.excluded')}</p>

        {/* Enable */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('global.enable')}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{t('global.enableHelp')}</p>
          </div>
          <button
            type="button"
            onClick={() => setEnabled(!enabled)}
            role="switch"
            aria-checked={enabled}
            aria-label={t('global.enable')}
            className={`relative w-12 h-6 rounded-full transition-colors shrink-0 ${enabled ? 'bg-primary-600' : 'bg-slate-300 dark:bg-slate-600'}`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${enabled ? 'translate-x-6' : ''}`}
            />
          </button>
        </div>

        {/* Trusted Proxies is empty: right for a server reached directly, wrong behind a CDN (#400) */}
        {needsConfirm && (
          <div className="p-4 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20">
            <div className="flex items-start gap-3">
              <input
                ref={confirmRef}
                id={confirmId}
                type="checkbox"
                checked={confirmNoProxy}
                onChange={(e) => {
                  setConfirmNoProxy(e.target.checked)
                  if (e.target.checked) setError(null)
                }}
                aria-invalid={error !== null && confirmMissing}
                aria-describedby={error !== null && confirmMissing ? errorId : undefined}
                className="mt-0.5 w-4 h-4 flex-shrink-0 rounded border-slate-300 text-primary-600 focus:ring-2 focus:ring-primary-500"
              />
              <div>
                <label htmlFor={confirmId} className="text-sm font-medium text-amber-900 dark:text-amber-100">
                  {t('global.confirmNoProxy')}
                </label>
                <p className="text-xs text-amber-800 dark:text-amber-200 mt-1">{t('global.confirmNoProxyHelp')}</p>
              </div>
            </div>
          </div>
        )}

        {/* Leave LAN addresses alone — every jail, per-host ones included (#384) */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('global.ignorePrivate')}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{t('global.ignorePrivateHelp')}</p>
          </div>
          <button
            type="button"
            onClick={() => setIgnorePrivate(!ignorePrivate)}
            role="switch"
            aria-checked={ignorePrivate}
            aria-label={t('global.ignorePrivate')}
            className={`relative w-12 h-6 rounded-full transition-colors shrink-0 ${ignorePrivate ? 'bg-primary-600' : 'bg-slate-300 dark:bg-slate-600'}`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${ignorePrivate ? 'translate-x-6' : ''}`}
            />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
              {t('settings.maxRetries')}
              <HelpTip content={t('global.maxRetriesHelp')} />
            </label>
            <input
              type="number"
              min={1}
              value={maxRetries}
              onChange={(e) => setMaxRetries(Number(e.target.value))}
              className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
              {t('settings.findTime')}
              <HelpTip content={t('settings.findTimeHelp')} />
            </label>
            <input
              type="number"
              min={1}
              value={findTime}
              onChange={(e) => setFindTime(Number(e.target.value))}
              className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
              {t('settings.banTime')}
              <HelpTip content={t('settings.banTimeHelp')} />
            </label>
            <select
              value={customBanTime ? CUSTOM_DURATION : banTime}
              onChange={(e) => {
                const v = Number(e.target.value)
                setBanTime(v === CUSTOM_DURATION ? 600 : v)
              }}
              className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
            >
              {BAN_DURATIONS.map((d) => (
                <option key={d.key} value={d.seconds}>
                  {t(`bannedIp.durations.${d.key}`, { ns: 'waf' })}
                </option>
              ))}
              <option value={CUSTOM_DURATION}>{t('settings.banTimeCustom')}</option>
            </select>
            {customBanTime && (
              <input
                type="number"
                min={0}
                value={banTime}
                onChange={(e) => setBanTime(Number(e.target.value))}
                placeholder={t('settings.banTimeSecondsPlaceholder')}
                className="mt-2 w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
              />
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
              {t('settings.action')}
              <HelpTip content={t('global.actionHelp')} />
            </label>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
            >
              <option value="log">{t('settings.actionOptions.log')}</option>
              <option value="notify">{t('settings.actionOptions.notify')}</option>
              <option value="block">{t('settings.actionOptions.block')}</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
            {t('settings.failCodes')}
            <HelpTip content={t('global.failCodesHelp')} />
          </label>
          <input
            type="text"
            value={failCodes}
            onChange={(e) => setFailCodes(e.target.value)}
            className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-100 rounded-lg focus:ring-2 focus:ring-primary-500"
          />
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('global.failCodesNote')}</p>
        </div>

        {error && (
          <div className="p-3 rounded-lg border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20">
            <p id={errorId} role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={save}
            disabled={mutation.isPending}
            className="px-4 py-2 rounded-lg font-medium bg-primary-600 hover:bg-primary-700 text-white transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? t('common:status.saving') : t('common:buttons.save')}
          </button>
          {saved && <span className="text-sm text-green-600 dark:text-green-400">{t('global.saved')}</span>}
        </div>
      </div>
    </div>
  )
}

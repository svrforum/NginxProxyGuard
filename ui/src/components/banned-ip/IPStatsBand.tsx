import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { fetchBannedIPStats, BANNED_IP_STATS_WINDOWS } from '../../api/banned-ips'
import type { BannedIPStatsWindow, BannedIPTarget } from '../../api/banned-ips'

/** Flag for a two-letter country code, or null when we have no geo for this IP. */
function flagOf(code?: string): string | null {
  if (!code || code.length !== 2 || !/^[A-Za-z]{2}$/.test(code)) return null
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0)))
}

/** Whole days since `iso`, or null when the field is absent. */
function daysSince(iso?: string): number | null {
  if (!iso) return null
  return Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000))
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: 'danger' }) {
  return (
    <div>
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div
        className={`text-lg font-semibold tabular-nums ${
          tone === 'danger' ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-slate-100'
        }`}
      >
        {value}
      </div>
    </div>
  )
}

/**
 * Top targets are user-controlled strings of unbounded length, so each is
 * clipped and the row is capped — an attacker's 2KB URI must not be able to
 * push the rest of the band off screen.
 */
function Targets({ label, items }: { label: string; items: BannedIPTarget[] }) {
  if (items.length === 0) return null
  return (
    <div className="flex gap-2 text-xs">
      <span className="shrink-0 text-slate-500 dark:text-slate-400">{label}</span>
      <span className="min-w-0 flex flex-wrap gap-x-2 gap-y-1">
        {items.map((item) => (
          <span key={item.name} className="font-mono text-slate-700 dark:text-slate-300">
            <span className="inline-block max-w-[16rem] truncate align-bottom" title={item.name}>
              {item.name}
            </span>
            <span className="text-slate-400 dark:text-slate-500"> ({item.count.toLocaleString()})</span>
          </span>
        ))}
      </span>
    </div>
  )
}

/**
 * The summary above the log list: where this address is, what it asked for
 * inside the chosen window, and how often it has been banned before. (#242)
 *
 * The window is a closed set because a per-IP scan cannot use the client_ip
 * index inside compressed chunks — an open-ended range would walk the whole
 * hypertable.
 */
export function IPStatsBand({ ip }: { ip: string }) {
  const { t } = useTranslation(['waf', 'common'])
  const [days, setDays] = useState<BannedIPStatsWindow>(7)

  const { data, isLoading, error } = useQuery({
    queryKey: ['banned-ip-stats', ip, days],
    queryFn: () => fetchBannedIPStats(ip, days),
  })

  const flag = flagOf(data?.country_code)

  const firstSeenLabel = (iso?: string): string => {
    const days = daysSince(iso)
    if (days === null) return '—'
    return days === 0 ? t('bannedIp.ipStats.today') : t('bannedIp.ipStats.daysAgo', { days })
  }

  return (
    <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-900/30">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 text-sm">
          {flag && <span className="text-base leading-none">{flag}</span>}
          <span className="font-medium text-slate-700 dark:text-slate-200">
            {data?.country || t('bannedIp.ipStats.unknownCountry')}
          </span>
        </div>
        <div className="flex rounded-lg border border-slate-300 dark:border-slate-600 overflow-hidden">
          {BANNED_IP_STATS_WINDOWS.map((w) => (
            <button
              key={w}
              onClick={() => setDays(w)}
              aria-pressed={days === w}
              className={`px-2.5 py-1 text-xs font-medium transition-colors ${
                days === w
                  ? 'bg-primary-600 text-white'
                  : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700'
              }`}
            >
              {t('bannedIp.ipStats.window', { days: w })}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="h-14 flex items-center text-sm text-slate-400">{t('common:status.loading')}</div>
      ) : error ? (
        <div className="h-14 flex items-center text-sm text-slate-500 dark:text-slate-400">
          {t('bannedIp.ipStats.fetchError')}
        </div>
      ) : data ? (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-3">
            <Metric label={t('bannedIp.ipStats.totalRequests')} value={data.total_requests.toLocaleString()} />
            <Metric
              label={t('bannedIp.ipStats.blockedRequests')}
              value={data.blocked_requests.toLocaleString()}
              tone="danger"
            />
            <Metric label={t('bannedIp.ipStats.banCount')} value={t('bannedIp.ipStats.times', { n: data.ban_count })} />
            <Metric label={t('bannedIp.ipStats.firstSeen')} value={firstSeenLabel(data.first_seen)} />
          </div>
          {data.total_requests === 0 ? (
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('bannedIp.ipStats.noTrafficInWindow')}</p>
          ) : (
            <div className="space-y-1">
              <Targets label={t('bannedIp.ipStats.topHosts')} items={data.top_hosts} />
              <Targets label={t('bannedIp.ipStats.topURIs')} items={data.top_uris} />
            </div>
          )}
        </>
      ) : null}
    </div>
  )
}

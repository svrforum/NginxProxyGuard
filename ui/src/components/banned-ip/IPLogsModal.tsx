import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ModalShell } from '../common/ModalShell'
import { fetchIPLogs } from '../../api/banned-ips'
import type { BannedIP } from '../../api/banned-ips'
import { IPStatsBand } from './IPStatsBand'
import { BanDurationEditor } from './BanDurationEditor'

function formatDate(dateStr: string, locale?: string): string {
  return new Date(dateStr).toLocaleString(locale || 'ko-KR')
}

function getStatusColor(statusCode?: number): string {
  if (!statusCode) return 'text-slate-500'
  if (statusCode >= 500) return 'text-red-600 bg-red-50'
  if (statusCode >= 400) return 'text-amber-600 bg-amber-50'
  if (statusCode >= 300) return 'text-blue-600 bg-blue-50'
  return 'text-green-600 bg-green-50'
}

/**
 * Activity for one address: the ban that is in force (when there is one), the
 * traffic summary, and the recent log lines.
 *
 * `ban` is optional so the same modal serves the ban HISTORY tab, where a row
 * describes a past event rather than a live ban and there is no expiry or fail
 * count to show. (#250)
 */
export function IPLogsModal({ ipAddress, ban, hostName, onClose }: { ipAddress: string; ban?: BannedIP; hostName?: string; onClose: () => void }) {
  const { t, i18n } = useTranslation(['waf', 'common'])
  const { data, isLoading, error } = useQuery({
    queryKey: ['ip-logs', ipAddress],
    queryFn: () => fetchIPLogs(ipAddress),
  })

  const logs = data?.data || []

  return (
    <ModalShell isOpen onClose={onClose} panelClassName="max-w-4xl">
      <div className="flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <span className="font-mono bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200 px-2 py-0.5 rounded">{ipAddress}</span>
              {t('bannedIp.logs.title')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {ban?.reason ? `${t('bannedIp.logs.reasonPrefix')}${ban.reason}` : t('bannedIp.logs.subtitle')}
            </p>
          </div>
          <button onClick={onClose} aria-label={t('common:buttons.close')} className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        {/* The ban in force. Absent from the history tab, where a row is a past
            event and there is no expiry or fail count to report. (#250) */}
        {ban && (
          <div className="px-6 py-3 bg-red-50 dark:bg-red-900/10 border-b border-red-100 dark:border-red-900/30 flex flex-wrap items-center gap-4 text-sm">
            <div>
              <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.banTime')}</span>
              <span className="ml-2 text-red-700 dark:text-red-300">{formatDate(ban.banned_at, i18n.language)}</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.expires')}</span>
              <span className="text-red-700 dark:text-red-300">
                {ban.is_permanent ? t('bannedIp.status.permanent') : ban.expires_at ? formatDate(ban.expires_at, i18n.language) : '-'}
              </span>
              <BanDurationEditor banId={ban.id} isPermanent={ban.is_permanent} />
            </div>
            <div>
              <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.failCount')}</span>
              <span className="ml-2 text-red-700 dark:text-red-300">{ban.fail_count}</span>
            </div>
            {hostName && (
              <div>
                <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.host', { defaultValue: '호스트:' })}</span>
                <span className="ml-2 text-red-700 dark:text-red-300">{hostName}</span>
              </div>
            )}
            {ban.is_auto_banned && (
              <span className="px-2 py-0.5 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 text-xs font-medium rounded">
                {t('bannedIp.type.auto', { defaultValue: '자동 차단' })}
              </span>
            )}
          </div>
        )}

        <IPStatsBand ip={ipAddress} />

        {/* Logs Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            </div>
          ) : error ? (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">
              {t('bannedIp.logs.fetchError')}
            </div>
          ) : logs.length === 0 ? (
            <div className="text-center py-12 text-slate-500 dark:text-slate-400"><p>{t('bannedIp.logs.noLogs')}</p></div>
          ) : (
            <div className="space-y-2">
              {logs.map((log) => (
                <div key={log.id} className="p-3 bg-slate-50 dark:bg-slate-700/30 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${log.log_type === 'modsec' ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400' : log.log_type === 'error' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' : 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400'}`}>
                        {log.log_type === 'modsec' ? 'WAF' : log.log_type?.toUpperCase()}
                      </span>
                      {log.status_code && (<span className={`px-2 py-0.5 text-xs font-medium rounded ${getStatusColor(log.status_code)}`}>{log.status_code}</span>)}
                      {log.severity && (
                        <span className={`px-2 py-0.5 text-xs font-medium rounded ${log.severity === 'CRITICAL' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' : log.severity === 'WARNING' ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400' : 'bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300'}`}>{log.severity}</span>
                      )}
                    </div>
                    <span className="text-xs text-slate-400 dark:text-slate-500">{formatDate(log.timestamp, i18n.language)}</span>
                  </div>
                  {log.request_uri && (<div className="font-mono text-sm text-slate-700 dark:text-slate-300 mb-1"><span className="text-slate-500">{log.request_method}</span> {log.request_uri}</div>)}
                  {log.rule_message && (<div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/10 rounded px-2 py-1 mt-1"><span className="font-medium">Rule {log.rule_id}:</span> {log.rule_message}</div>)}
                  {log.host && (<div className="text-xs text-slate-500 mt-1">{t('bannedIp.logs.host')} {log.host}</div>)}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 flex justify-end">
          <button onClick={onClose} className="px-4 py-2 bg-slate-600 text-white rounded-lg hover:bg-slate-700">{t('bannedIp.logs.close')}</button>
        </div>
      </div>
    </ModalShell>
  )
}

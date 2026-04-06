import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { getIPBanHistory, getIPBanHistoryStats } from '../../api/security'
import type { BanEventType, BanSource } from '../../types/security'

export function BanHistoryTab({ hostMap }: { hostMap: Record<string, string> }) {
  const { t, i18n } = useTranslation('waf')
  const [page, setPage] = useState(1)
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all')
  const [sourceFilter, setSourceFilter] = useState<string>('all')

  const { data, isLoading, error } = useQuery({
    queryKey: ['ip-ban-history', page, eventTypeFilter, sourceFilter],
    queryFn: () => getIPBanHistory({
      event_type: eventTypeFilter !== 'all' ? eventTypeFilter as BanEventType : undefined,
      source: sourceFilter !== 'all' ? sourceFilter as BanSource : undefined,
      page, per_page: 30,
    }),
    refetchInterval: 60000,
  })

  const { data: statsData } = useQuery({
    queryKey: ['ip-ban-history-stats'],
    queryFn: getIPBanHistoryStats,
    refetchInterval: 120000,
  })

  const history = data?.data || []
  const totalPages = data?.total_pages || 1
  const stats = statsData

  const getEventTypeColor = (eventType: string) => eventType === 'ban'
    ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
    : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'

  const getSourceColor = (source: string) => {
    switch (source) {
      case 'fail2ban': return 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400'
      case 'waf_auto_ban': return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400'
      case 'manual': return 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400'
      case 'expired': return 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
      default: return 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
    }
  }

  const getSourceLabel = (source: string) => {
    const labels: Record<string, string> = {
      fail2ban: 'Fail2ban', waf_auto_ban: 'WAF Auto',
      manual: t('bannedIp.history.source.manual', { defaultValue: '수동' }),
      api: 'API', expired: t('bannedIp.history.source.expired', { defaultValue: '만료' }),
    }
    return labels[source] || source
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">{stats.total_bans}</div>
            <div className="text-sm text-slate-500 dark:text-slate-400">{t('bannedIp.history.stats.totalBans', { defaultValue: '총 차단' })}</div>
          </div>
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.total_unbans}</div>
            <div className="text-sm text-slate-500 dark:text-slate-400">{t('bannedIp.history.stats.totalUnbans', { defaultValue: '총 해제' })}</div>
          </div>
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
            <div className="text-2xl font-bold text-slate-900 dark:text-white">{stats.active_bans}</div>
            <div className="text-sm text-slate-500 dark:text-slate-400">{t('bannedIp.history.stats.activeBans', { defaultValue: '현재 활성' })}</div>
          </div>
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
            <div className="text-2xl font-bold text-amber-600 dark:text-amber-400">{stats.bans_by_source?.fail2ban || 0}</div>
            <div className="text-sm text-slate-500 dark:text-slate-400">{t('bannedIp.history.stats.fail2ban', { defaultValue: 'Fail2ban 차단' })}</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('bannedIp.history.filter.eventType', { defaultValue: '이벤트 유형' })}</label>
            <select value={eventTypeFilter} onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1); }} className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 dark:text-white">
              <option value="all">{t('bannedIp.history.filter.all', { defaultValue: '모두' })}</option>
              <option value="ban">{t('bannedIp.history.filter.ban', { defaultValue: '차단' })}</option>
              <option value="unban">{t('bannedIp.history.filter.unban', { defaultValue: '해제' })}</option>
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('bannedIp.history.filter.source', { defaultValue: '소스' })}</label>
            <select value={sourceFilter} onChange={(e) => { setSourceFilter(e.target.value); setPage(1); }} className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 dark:text-white">
              <option value="all">{t('bannedIp.history.filter.all', { defaultValue: '모두' })}</option>
              <option value="fail2ban">Fail2ban</option>
              <option value="waf_auto_ban">WAF Auto Ban</option>
              <option value="manual">{t('bannedIp.history.filter.manual', { defaultValue: '수동' })}</option>
              <option value="expired">{t('bannedIp.history.filter.expired', { defaultValue: '만료' })}</option>
            </select>
          </div>
        </div>
      </div>

      {/* History Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        </div>
      ) : error ? (
        <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">{t('bannedIp.history.fetchError', { defaultValue: '이력을 불러오는 데 실패했습니다.' })}</div>
      ) : history.length === 0 ? (
        <div className="text-center py-12 text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
          <svg className="w-16 h-16 mx-auto mb-4 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          <p>{t('bannedIp.history.noHistory', { defaultValue: '이력이 없습니다.' })}</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-700/50 border-b border-slate-200 dark:border-slate-700">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.time', { defaultValue: '시간' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.event', { defaultValue: '이벤트' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.ip', { defaultValue: 'IP 주소' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.source', { defaultValue: '소스' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.host', { defaultValue: '호스트' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.reason', { defaultValue: '사유' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.history.table.user', { defaultValue: '사용자' })}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
              {history.map((item) => {
                const hostName = item.proxy_host_id ? hostMap[item.proxy_host_id] : item.domain_name
                return (
                  <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50">
                    <td className="px-4 py-3"><span className="text-sm text-slate-600 dark:text-slate-300">{new Date(item.created_at).toLocaleString(i18n.language)}</span></td>
                    <td className="px-4 py-3"><span className={`px-2 py-0.5 text-xs font-medium rounded ${getEventTypeColor(item.event_type)}`}>{item.event_type === 'ban' ? t('bannedIp.history.event.ban', { defaultValue: '차단' }) : t('bannedIp.history.event.unban', { defaultValue: '해제' })}</span></td>
                    <td className="px-4 py-3"><span className="font-mono text-sm text-slate-900 dark:text-slate-100">{item.ip_address}</span></td>
                    <td className="px-4 py-3"><span className={`px-2 py-0.5 text-xs font-medium rounded ${getSourceColor(item.source)}`}>{getSourceLabel(item.source)}</span></td>
                    <td className="px-4 py-3">
                      {hostName ? (
                        <span className="text-sm text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">{hostName}</span>
                      ) : (
                        <span className="text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 px-2 py-0.5 rounded font-medium">{t('bannedIp.global', { defaultValue: '전역' })}</span>
                      )}
                    </td>
                    <td className="px-4 py-3"><span className="text-sm text-slate-600 dark:text-slate-300 max-w-[200px] truncate block" title={item.reason}>{item.reason || '-'}</span></td>
                    <td className="px-4 py-3"><span className="text-sm text-slate-500 dark:text-slate-400">{item.user_email || (item.is_auto ? t('bannedIp.history.system', { defaultValue: '시스템' }) : '-')}</span></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">{t('pagination.prev', { defaultValue: '이전' })}</button>
          <span className="px-4 py-1.5 text-sm text-slate-600 dark:text-slate-400">{page} / {totalPages}</span>
          <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">{t('pagination.next', { defaultValue: '다음' })}</button>
        </div>
      )}

      {/* Top Banned IPs */}
      {stats?.top_banned_ips && stats.top_banned_ips.length > 0 && (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">{t('bannedIp.history.topBanned', { defaultValue: '자주 차단된 IP' })}</h3>
          <div className="space-y-2">
            {stats.top_banned_ips.slice(0, 5).map((item, index) => (
              <div key={item.ip_address} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 flex items-center justify-center bg-slate-200 dark:bg-slate-600 rounded-full text-xs font-medium text-slate-600 dark:text-slate-300">{index + 1}</span>
                  <span className="font-mono text-sm text-slate-900 dark:text-slate-100">{item.ip_address}</span>
                </div>
                <span className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 text-sm font-medium rounded">{item.ban_count} {t('bannedIp.history.times', { defaultValue: '회' })}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

import { useState, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getAuthHeaders } from '../api/auth'
import { HelpTip } from './common/HelpTip'
import { useEscapeKey } from '../hooks/useEscapeKey'
import { getIPBanHistory, getIPBanHistoryStats } from '../api/security'
import type { BanEventType, BanSource } from '../types/security'

interface BannedIP {
  id: string
  proxy_host_id?: string
  ip_address: string
  reason?: string
  fail_count: number
  banned_at: string
  expires_at?: string
  is_permanent: boolean
  is_auto_banned?: boolean
  created_at: string
}

interface BannedIPListResponse {
  data: BannedIP[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

interface ProxyHost {
  id: string
  domain_names: string[]
  enabled: boolean
}

interface ProxyHostListResponse {
  data: ProxyHost[]
  total: number
}

interface LogEntry {
  id: string
  log_type: string
  timestamp: string
  host?: string
  client_ip?: string
  request_method?: string
  request_uri?: string
  status_code?: number
  rule_id?: number
  rule_message?: string
  severity?: string
}

interface LogListResponse {
  data: LogEntry[]
  total: number
}

const API_BASE = '/api/v1'

async function fetchBannedIPs(page = 1, perPage = 50, proxyHostId?: string, filter?: string): Promise<BannedIPListResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    per_page: perPage.toString(),
  })
  if (filter) {
    params.set('filter', filter)
  }
  if (proxyHostId) {
    params.set('proxy_host_id', proxyHostId)
  }
  const res = await fetch(`${API_BASE}/banned-ips?${params}`, {
    headers: getAuthHeaders(),
  })
  if (!res.ok) throw new Error('Failed to fetch banned IPs')
  return res.json()
}

async function fetchProxyHosts(): Promise<ProxyHostListResponse> {
  const res = await fetch(`${API_BASE}/proxy-hosts?page=1&per_page=100`, {
    headers: getAuthHeaders(),
  })
  if (!res.ok) throw new Error('Failed to fetch proxy hosts')
  return res.json()
}

async function unbanIP(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/banned-ips/${id}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  })
  if (!res.ok) throw new Error('Failed to unban IP')
}

async function banIP(data: {
  ip_address: string
  reason?: string
  ban_time?: number
  proxy_host_id?: string
}): Promise<BannedIP> {
  const res = await fetch(`${API_BASE}/banned-ips`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error('Failed to ban IP')
  return res.json()
}

async function fetchIPLogs(ip: string): Promise<LogListResponse> {
  const params = new URLSearchParams({
    client_ip: ip,
    per_page: '100',
  })
  const res = await fetch(`${API_BASE}/logs?${params}`, {
    headers: getAuthHeaders(),
  })
  if (!res.ok) throw new Error('Failed to fetch logs')
  return res.json()
}

function formatDate(dateStr: string, locale?: string): string {
  return new Date(dateStr).toLocaleString(locale || 'ko-KR')
}

function formatRelativeTime(dateStr: string, t: (key: string, options?: { count?: number }) => string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffSec < 0) {
    // Future date (expires_at)
    const futureSec = Math.abs(diffSec)
    const futureMin = Math.floor(futureSec / 60)
    const futureHour = Math.floor(futureMin / 60)
    const futureDay = Math.floor(futureHour / 24)

    if (futureDay > 0) return t('bannedIp.time.futureDays', { count: futureDay })
    if (futureHour > 0) return t('bannedIp.time.futureHours', { count: futureHour })
    if (futureMin > 0) return t('bannedIp.time.futureMinutes', { count: futureMin })
    return t('bannedIp.time.soon')
  }

  if (diffSec < 60) return t('bannedIp.time.justNow')
  if (diffMin < 60) return t('bannedIp.time.minutesAgo', { count: diffMin })
  if (diffHour < 24) return t('bannedIp.time.hoursAgo', { count: diffHour })
  return t('bannedIp.time.daysAgo', { count: diffDay })
}

function getTimeRemaining(expiresAt: string | undefined, t: (key: string, options?: { count?: number }) => string): { text: string; color: string } | null {
  if (!expiresAt) return null

  const expires = new Date(expiresAt)
  const now = new Date()
  const diffMs = expires.getTime() - now.getTime()

  // Expired bans are filtered out by the API, but just in case
  if (diffMs <= 0) {
    return null
  }

  const diffMin = Math.floor(diffMs / 60000)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  if (diffDay > 0) return { text: t('bannedIp.status.daysRemaining', { count: diffDay }), color: 'text-amber-600' }
  if (diffHour > 0) return { text: t('bannedIp.status.hoursRemaining', { count: diffHour }), color: 'text-amber-600' }
  if (diffMin > 0) return { text: t('bannedIp.status.minutesRemaining', { count: diffMin }), color: 'text-red-600' }
  return { text: t('bannedIp.status.expiringSoon'), color: 'text-red-600' }
}

function getStatusColor(statusCode?: number): string {
  if (!statusCode) return 'text-slate-500'
  if (statusCode >= 500) return 'text-red-600 bg-red-50'
  if (statusCode >= 400) return 'text-amber-600 bg-amber-50'
  if (statusCode >= 300) return 'text-blue-600 bg-blue-50'
  return 'text-green-600 bg-green-50'
}

// Parse reason to get category
function getReasonCategory(reason?: string): string {
  if (!reason) return 'manual'
  const lowerReason = reason.toLowerCase()
  if (lowerReason.includes('waf') || lowerReason.includes('modsec') || lowerReason.includes('rule')) return 'waf'
  if (lowerReason.includes('fail2ban') || lowerReason.includes('failed')) return 'fail2ban'
  if (lowerReason.includes('rate') || lowerReason.includes('limit')) return 'rate_limit'
  if (lowerReason.includes('bot')) return 'bot'
  if (lowerReason.includes('auto')) return 'auto'
  return 'manual'
}

export function BannedIPList() {
  const { t, i18n } = useTranslation('waf')
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [selectedIP, setSelectedIP] = useState<BannedIP | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [newBan, setNewBan] = useState({ ip_address: '', reason: '', ban_time: 3600, proxy_host_id: '' })

  // Tab state - global first, then per-host, then history
  const [activeTab, setActiveTab] = useState<'global' | 'hosts' | 'history'>('global')

  // Filters
  const [hostFilter, setHostFilter] = useState<string>('all')
  const [typeFilter, setTypeFilter] = useState<string>('all')

  // Fetch proxy hosts for filtering and display
  const { data: hostsData } = useQuery({
    queryKey: ['proxy-hosts-list'],
    queryFn: fetchProxyHosts,
  })

  const proxyHosts = useMemo(() => hostsData?.data || [], [hostsData?.data])
  const hostMap = useMemo(() => {
    const map: Record<string, string> = {}
    proxyHosts.forEach(h => {
      map[h.id] = h.domain_names[0] || h.id
    })
    return map
  }, [proxyHosts])

  const { data, isLoading, error } = useQuery({
    queryKey: ['banned-ips', page, activeTab, hostFilter],
    queryFn: () => {
      const filter = activeTab === 'global' ? 'global' : activeTab === 'hosts' ? 'host' : undefined
      const proxyHostId = activeTab === 'hosts' && hostFilter !== 'all' ? hostFilter : undefined
      return fetchBannedIPs(page, 50, proxyHostId, filter)
    },
    refetchInterval: 30000,
  })

  // Client-side filtering for type filter only (global/hosts filtering is server-side)
  const filteredBannedIPs = useMemo(() => {
    if (!data?.data) return []

    if (typeFilter === 'all') return data.data

    return data.data.filter(ban => {
      const category = getReasonCategory(ban.reason)
      if (typeFilter === 'auto') return ban.is_auto_banned
      if (typeFilter === 'manual') return !ban.is_auto_banned
      return category === typeFilter
    })
  }, [data?.data, typeFilter])

  const unbanMutation = useMutation({
    mutationFn: unbanIP,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] })
    },
  })

  const banMutation = useMutation({
    mutationFn: banIP,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] })
      setShowAddModal(false)
      setNewBan({ ip_address: '', reason: '', ban_time: 3600, proxy_host_id: '' })
    },
  })

  const handleUnban = (id: string, ip: string) => {
    if (confirm(t('bannedIp.confirm.unban', { ip }))) {
      unbanMutation.mutate(id)
    }
  }

  const handleBan = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newBan.ip_address) return
    const payload: { ip_address: string; reason?: string; ban_time?: number; proxy_host_id?: string } = {
      ip_address: newBan.ip_address,
      reason: newBan.reason || undefined,
      ban_time: newBan.ban_time,
    }
    if (newBan.proxy_host_id) {
      payload.proxy_host_id = newBan.proxy_host_id
    }
    banMutation.mutate(payload)
  }

  const total = data?.total || 0
  const totalPages = data?.total_pages || 1

  // Statistics
  const stats = useMemo(() => {
    const bans = data?.data || []
    return {
      total: bans.length,
      permanent: bans.filter(b => b.is_permanent).length,
      auto: bans.filter(b => b.is_auto_banned).length,
      byHost: bans.reduce((acc, b) => {
        const key = b.proxy_host_id || 'global'
        acc[key] = (acc[key] || 0) + 1
        return acc
      }, {} as Record<string, number>),
    }
  }, [data?.data])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-slate-900 dark:text-white">{t('bannedIp.title')}</h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
            {t('bannedIp.subtitle')}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            {t('bannedIp.addBan')}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-700">
        <nav className="flex gap-4" aria-label="Tabs">
          <button
            onClick={() => { setActiveTab('global'); setPage(1); }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'global'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300'
            }`}
          >
            {t('bannedIp.tabs.global', { defaultValue: '전역 차단' })}
            {activeTab === 'global' && (
              <span className="ml-2 px-2 py-0.5 text-xs bg-slate-100 dark:bg-slate-700 rounded-full">
                {total}
              </span>
            )}
          </button>
          <button
            onClick={() => { setActiveTab('hosts'); setPage(1); }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'hosts'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300'
            }`}
          >
            {t('bannedIp.tabs.perHost', { defaultValue: '호스트별 차단' })}
            {activeTab === 'hosts' && (
              <span className="ml-2 px-2 py-0.5 text-xs bg-slate-100 dark:bg-slate-700 rounded-full">
                {total}
              </span>
            )}
          </button>
          <button
            onClick={() => { setActiveTab('history'); setPage(1); }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'history'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300'
            }`}
          >
            {t('bannedIp.tabs.history', { defaultValue: '차단 이력' })}
          </button>
        </nav>
      </div>

      {activeTab === 'history' ? (
        <BanHistoryTab hostMap={hostMap} />
      ) : (
        <>

      {/* Statistics Cards - only show for global/hosts tabs */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
          <div className="text-2xl font-bold text-slate-900 dark:text-white">{total}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">
            {activeTab === 'global' ? t('bannedIp.stats.global', { defaultValue: '전역 차단' }) : t('bannedIp.stats.total', { defaultValue: '호스트별 차단' })}
          </div>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
          <div className="text-2xl font-bold text-red-600 dark:text-red-400">{stats.permanent}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">{t('bannedIp.stats.permanent', { defaultValue: '영구 차단' })}</div>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
          <div className="text-2xl font-bold text-amber-600 dark:text-amber-400">{stats.auto}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">{t('bannedIp.stats.auto', { defaultValue: '자동 차단' })}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
        <div className="flex flex-wrap gap-4">
          {/* Host Filter - only show on hosts tab */}
          {activeTab === 'hosts' && (
            <div className="flex-1 min-w-[200px]">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('bannedIp.filter.host', { defaultValue: '호스트' })}
              </label>
              <select
                value={hostFilter}
                onChange={(e) => { setHostFilter(e.target.value); setPage(1); }}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 dark:text-white"
              >
                <option value="all">{t('bannedIp.filter.allHosts', { defaultValue: '모든 호스트' })}</option>
                {proxyHosts.map(host => (
                  <option key={host.id} value={host.id}>
                    {host.domain_names[0]} {stats.byHost[host.id] ? `(${stats.byHost[host.id]})` : ''}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Type Filter */}
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('bannedIp.filter.type', { defaultValue: '차단 유형' })}
            </label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="all">{t('bannedIp.filter.allTypes', { defaultValue: '모든 유형' })}</option>
              <option value="auto">{t('bannedIp.filter.autoOnly', { defaultValue: '자동 차단' })}</option>
              <option value="manual">{t('bannedIp.filter.manualOnly', { defaultValue: '수동 차단' })}</option>
              <option value="waf">{t('bannedIp.filter.waf', { defaultValue: 'WAF 차단' })}</option>
              <option value="fail2ban">{t('bannedIp.filter.fail2ban', { defaultValue: 'Fail2ban' })}</option>
              <option value="rate_limit">{t('bannedIp.filter.rateLimit', { defaultValue: 'Rate Limit' })}</option>
            </select>
          </div>

          {/* Results count */}
          <div className="flex items-end">
            <span className="text-sm text-slate-500 dark:text-slate-400 pb-2">
              {t('bannedIp.filter.showing', { defaultValue: '표시: {{count}}건', count: filteredBannedIPs.length })}
            </span>
          </div>
        </div>
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        </div>
      ) : error ? (
        <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">
          {t('bannedIp.fetchError')}
        </div>
      ) : filteredBannedIPs.length === 0 ? (
        <div className="text-center py-12 text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
          <svg className="w-16 h-16 mx-auto mb-4 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <p>{t('bannedIp.noBans')}</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-700/50 border-b border-slate-200 dark:border-slate-700">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.ip')}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.host', { defaultValue: '호스트' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.reason')}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.type', { defaultValue: '유형' })}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.banTime')}</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.expires')}</th>
                <th className="text-right px-4 py-3 text-sm font-medium text-slate-600 dark:text-slate-300">{t('bannedIp.table.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
              {filteredBannedIPs.map((ban) => {
                const timeRemaining = ban.is_permanent ? null : getTimeRemaining(ban.expires_at, t)
                const hostName = ban.proxy_host_id ? hostMap[ban.proxy_host_id] : null

                return (
                  <tr key={ban.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50">
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedIP(ban)}
                        className="font-mono text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 hover:underline"
                      >
                        {ban.ip_address}
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      {hostName ? (
                        <span className="text-sm text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">
                          {hostName}
                        </span>
                      ) : (
                        <span className="text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 px-2 py-0.5 rounded font-medium">
                          {t('bannedIp.global', { defaultValue: '전역' })}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-slate-600 dark:text-slate-300 max-w-[200px] truncate block" title={ban.reason}>
                        {ban.reason || '-'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {ban.is_auto_banned ? (
                        <span className="px-2 py-0.5 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 text-xs font-medium rounded">
                          {t('bannedIp.type.auto', { defaultValue: '자동' })}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 text-xs font-medium rounded">
                          {t('bannedIp.type.manual', { defaultValue: '수동' })}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-slate-500 dark:text-slate-400" title={formatDate(ban.banned_at, i18n.language)}>
                        {formatRelativeTime(ban.banned_at, t)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {ban.is_permanent ? (
                        <span className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 text-xs font-medium rounded-full">
                          {t('bannedIp.status.permanent')}
                        </span>
                      ) : timeRemaining ? (
                        <span className={`text-sm ${timeRemaining.color}`}>
                          {timeRemaining.text}
                        </span>
                      ) : (
                        <span className="text-sm text-slate-400 dark:text-slate-600">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleUnban(ban.id, ban.ip_address)}
                        disabled={unbanMutation.isPending}
                        className="px-3 py-1.5 text-sm text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg transition-colors"
                      >
                        {t('bannedIp.actions.unban')}
                      </button>
                    </td>
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
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.prev', { defaultValue: '이전' })}
          </button>
          <span className="px-4 py-1.5 text-sm text-slate-600 dark:text-slate-400">
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.next', { defaultValue: '다음' })}
          </button>
        </div>
      )}

      {/* IP Details Modal */}
      {selectedIP && (
        <IPLogsModal ip={selectedIP} hostName={selectedIP.proxy_host_id ? hostMap[selectedIP.proxy_host_id] : undefined} onClose={() => setSelectedIP(null)} />
      )}
        </>
      )}

      {/* Add Ban Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-md border border-slate-200 dark:border-slate-700">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{t('bannedIp.modal.title')}</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-2 text-slate-400 hover:text-slate-600 rounded-lg"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleBan} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('bannedIp.modal.ipLabel')}
                  <HelpTip contentKey="help.bannedIp.ip" ns="waf" />
                </label>
                <input
                  type="text"
                  value={newBan.ip_address}
                  onChange={(e) => setNewBan((prev) => ({ ...prev, ip_address: e.target.value }))}
                  placeholder={t('bannedIp.modal.ipPlaceholder')}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 font-mono bg-white dark:bg-slate-700 dark:text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('bannedIp.modal.hostLabel', { defaultValue: '적용 호스트' })}
                </label>
                <select
                  value={newBan.proxy_host_id}
                  onChange={(e) => setNewBan((prev) => ({ ...prev, proxy_host_id: e.target.value }))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 bg-white dark:bg-slate-700 dark:text-white"
                >
                  <option value="">{t('bannedIp.modal.globalBan', { defaultValue: '전역 차단 (모든 호스트)' })}</option>
                  {proxyHosts.map(host => (
                    <option key={host.id} value={host.id}>{host.domain_names[0]}</option>
                  ))}
                </select>
                <p className="text-xs text-slate-500 mt-1">
                  {t('bannedIp.modal.hostHint', { defaultValue: '전역 차단은 모든 프록시 호스트에 적용됩니다.' })}
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1 flex items-center gap-2">
                  {t('bannedIp.modal.reasonLabel')}
                  <HelpTip contentKey="help.bannedIp.reason" ns="waf" />
                </label>
                <input
                  type="text"
                  value={newBan.reason}
                  onChange={(e) => setNewBan((prev) => ({ ...prev, reason: e.target.value }))}
                  placeholder={t('bannedIp.modal.reasonPlaceholder')}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 bg-white dark:bg-slate-700 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('bannedIp.modal.durationLabel')}
                  <HelpTip contentKey="help.bannedIp.duration" ns="waf" />
                </label>
                <select
                  value={newBan.ban_time}
                  onChange={(e) => setNewBan((prev) => ({ ...prev, ban_time: parseInt(e.target.value) }))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 bg-white dark:bg-slate-700 dark:text-white"
                >
                  <option value={300}>{t('bannedIp.modal.durations.5m')}</option>
                  <option value={600}>{t('bannedIp.modal.durations.10m')}</option>
                  <option value={1800}>{t('bannedIp.modal.durations.30m')}</option>
                  <option value={3600}>{t('bannedIp.modal.durations.1h')}</option>
                  <option value={86400}>{t('bannedIp.modal.durations.24h')}</option>
                  <option value={604800}>{t('bannedIp.modal.durations.7d')}</option>
                  <option value={2592000}>{t('bannedIp.modal.durations.30d')}</option>
                  <option value={0}>{t('bannedIp.modal.durations.permanent')}</option>
                </select>
              </div>
              {banMutation.isError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
                  {t('bannedIp.messages.saveFailed', { defaultValue: '차단에 실패했습니다.' })}
                </div>
              )}
              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg"
                >
                  {t('bannedIp.actions.cancel')}
                </button>
                <button
                  type="submit"
                  disabled={banMutation.isPending}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:bg-red-400"
                >
                  {banMutation.isPending ? t('bannedIp.actions.processing') : t('bannedIp.actions.ban')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

// IP Logs Modal Component
function IPLogsModal({ ip, hostName, onClose }: { ip: BannedIP; hostName?: string; onClose: () => void }) {
  const { t, i18n } = useTranslation('waf')
  const { data, isLoading, error } = useQuery({
    queryKey: ['ip-logs', ip.ip_address],
    queryFn: () => fetchIPLogs(ip.ip_address),
  })

  useEscapeKey(onClose)

  const logs = data?.data || []

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col border border-slate-200 dark:border-slate-700">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <span className="font-mono bg-slate-200 dark:bg-slate-700 text-slate-800 dark:text-slate-200 px-2 py-0.5 rounded">{ip.ip_address}</span>
              {t('bannedIp.logs.title')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {ip.reason ? `${t('bannedIp.logs.reasonPrefix')}${ip.reason}` : t('bannedIp.logs.subtitle')}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Ban Info */}
        <div className="px-6 py-3 bg-red-50 dark:bg-red-900/10 border-b border-red-100 dark:border-red-900/30 flex flex-wrap items-center gap-4 text-sm">
          <div>
            <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.banTime')}</span>
            <span className="ml-2 text-red-700 dark:text-red-300">{formatDate(ip.banned_at, i18n.language)}</span>
          </div>
          <div>
            <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.expires')}</span>
            <span className="ml-2 text-red-700 dark:text-red-300">
              {ip.is_permanent ? t('bannedIp.status.permanent') : ip.expires_at ? formatDate(ip.expires_at, i18n.language) : '-'}
            </span>
          </div>
          <div>
            <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.failCount')}</span>
            <span className="ml-2 text-red-700 dark:text-red-300">{ip.fail_count}</span>
          </div>
          {hostName && (
            <div>
              <span className="text-red-600 dark:text-red-400 font-medium">{t('bannedIp.logs.host', { defaultValue: '호스트:' })}</span>
              <span className="ml-2 text-red-700 dark:text-red-300">{hostName}</span>
            </div>
          )}
          {ip.is_auto_banned && (
            <span className="px-2 py-0.5 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 text-xs font-medium rounded">
              {t('bannedIp.type.auto', { defaultValue: '자동 차단' })}
            </span>
          )}
        </div>

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
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
              {t('bannedIp.logs.fetchError')}
            </div>
          ) : logs.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <p>{t('bannedIp.logs.noLogs')}</p>
            </div>
          ) : (
            <div className="space-y-2">
              {logs.map((log) => (
                <div
                  key={log.id}
                  className="p-3 bg-slate-50 dark:bg-slate-700/30 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${log.log_type === 'modsec' ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400' :
                        log.log_type === 'error' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' :
                          'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400'
                        }`}>
                        {log.log_type === 'modsec' ? 'WAF' : log.log_type?.toUpperCase()}
                      </span>
                      {log.status_code && (
                        <span className={`px-2 py-0.5 text-xs font-medium rounded ${getStatusColor(log.status_code)}`}>
                          {log.status_code}
                        </span>
                      )}
                      {log.severity && (
                        <span className={`px-2 py-0.5 text-xs font-medium rounded ${log.severity === 'CRITICAL' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' :
                          log.severity === 'WARNING' ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400' :
                            'bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300'
                          }`}>
                          {log.severity}
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-slate-400 dark:text-slate-500">{formatDate(log.timestamp, i18n.language)}</span>
                  </div>

                  {log.request_uri && (
                    <div className="font-mono text-sm text-slate-700 dark:text-slate-300 mb-1">
                      <span className="text-slate-500">{log.request_method}</span> {log.request_uri}
                    </div>
                  )}

                  {log.rule_message && (
                    <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/10 rounded px-2 py-1 mt-1">
                      <span className="font-medium">Rule {log.rule_id}:</span> {log.rule_message}
                    </div>
                  )}

                  {log.host && (
                    <div className="text-xs text-slate-500 mt-1">
                      {t('bannedIp.logs.host')} {log.host}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-600 text-white rounded-lg hover:bg-slate-700"
          >
            {t('bannedIp.logs.close')}
          </button>
        </div>
      </div>
    </div>
  )
}

// Ban History Tab Component
function BanHistoryTab({ hostMap }: { hostMap: Record<string, string> }) {
  const { t, i18n } = useTranslation('waf')
  const [page, setPage] = useState(1)
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all')
  const [sourceFilter, setSourceFilter] = useState<string>('all')

  // Fetch history
  const { data, isLoading, error } = useQuery({
    queryKey: ['ip-ban-history', page, eventTypeFilter, sourceFilter],
    queryFn: () => getIPBanHistory({
      event_type: eventTypeFilter !== 'all' ? eventTypeFilter as BanEventType : undefined,
      source: sourceFilter !== 'all' ? sourceFilter as BanSource : undefined,
      page,
      per_page: 30,
    }),
    refetchInterval: 30000,
  })

  // Fetch stats
  const { data: statsData } = useQuery({
    queryKey: ['ip-ban-history-stats'],
    queryFn: getIPBanHistoryStats,
    refetchInterval: 60000,
  })

  const history = data?.data || []
  const totalPages = data?.total_pages || 1
  const stats = statsData

  const getEventTypeColor = (eventType: string) => {
    return eventType === 'ban'
      ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
      : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
  }

  const getSourceColor = (source: string) => {
    switch (source) {
      case 'fail2ban':
        return 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400'
      case 'waf_auto_ban':
        return 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400'
      case 'manual':
        return 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400'
      case 'expired':
        return 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
      default:
        return 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
    }
  }

  const getSourceLabel = (source: string) => {
    const labels: Record<string, string> = {
      fail2ban: 'Fail2ban',
      waf_auto_ban: 'WAF Auto',
      manual: t('bannedIp.history.source.manual', { defaultValue: '수동' }),
      api: 'API',
      expired: t('bannedIp.history.source.expired', { defaultValue: '만료' }),
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
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('bannedIp.history.filter.eventType', { defaultValue: '이벤트 유형' })}
            </label>
            <select
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1); }}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="all">{t('bannedIp.history.filter.all', { defaultValue: '모두' })}</option>
              <option value="ban">{t('bannedIp.history.filter.ban', { defaultValue: '차단' })}</option>
              <option value="unban">{t('bannedIp.history.filter.unban', { defaultValue: '해제' })}</option>
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('bannedIp.history.filter.source', { defaultValue: '소스' })}
            </label>
            <select
              value={sourceFilter}
              onChange={(e) => { setSourceFilter(e.target.value); setPage(1); }}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 dark:text-white"
            >
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
        <div className="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">
          {t('bannedIp.history.fetchError', { defaultValue: '이력을 불러오는 데 실패했습니다.' })}
        </div>
      ) : history.length === 0 ? (
        <div className="text-center py-12 text-slate-500 dark:text-slate-400 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
          <svg className="w-16 h-16 mx-auto mb-4 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
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
                    <td className="px-4 py-3">
                      <span className="text-sm text-slate-600 dark:text-slate-300" title={new Date(item.created_at).toLocaleString(i18n.language)}>
                        {new Date(item.created_at).toLocaleString(i18n.language)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${getEventTypeColor(item.event_type)}`}>
                        {item.event_type === 'ban' ? t('bannedIp.history.event.ban', { defaultValue: '차단' }) : t('bannedIp.history.event.unban', { defaultValue: '해제' })}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-sm text-slate-900 dark:text-slate-100">{item.ip_address}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSourceColor(item.source)}`}>
                        {getSourceLabel(item.source)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {hostName ? (
                        <span className="text-sm text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">
                          {hostName}
                        </span>
                      ) : (
                        <span className="text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 px-2 py-0.5 rounded font-medium">
                          {t('bannedIp.global', { defaultValue: '전역' })}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-slate-600 dark:text-slate-300 max-w-[200px] truncate block" title={item.reason}>
                        {item.reason || '-'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-slate-500 dark:text-slate-400">
                        {item.user_email || (item.is_auto ? t('bannedIp.history.system', { defaultValue: '시스템' }) : '-')}
                      </span>
                    </td>
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
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.prev', { defaultValue: '이전' })}
          </button>
          <span className="px-4 py-1.5 text-sm text-slate-600 dark:text-slate-400">
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.next', { defaultValue: '다음' })}
          </button>
        </div>
      )}

      {/* Top Banned IPs */}
      {stats?.top_banned_ips && stats.top_banned_ips.length > 0 && (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
            {t('bannedIp.history.topBanned', { defaultValue: '자주 차단된 IP' })}
          </h3>
          <div className="space-y-2">
            {stats.top_banned_ips.slice(0, 5).map((item, index) => (
              <div key={item.ip_address} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 flex items-center justify-center bg-slate-200 dark:bg-slate-600 rounded-full text-xs font-medium text-slate-600 dark:text-slate-300">
                    {index + 1}
                  </span>
                  <span className="font-mono text-sm text-slate-900 dark:text-slate-100">{item.ip_address}</span>
                </div>
                <span className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 text-sm font-medium rounded">
                  {item.ban_count} {t('bannedIp.history.times', { defaultValue: '회' })}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

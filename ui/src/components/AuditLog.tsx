import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { getAuthHeaders } from '../api/auth'

// Types
interface AuditLog {
  id: string
  username: string
  action: string
  action_label: string
  resource_type?: string
  resource_id?: string
  resource_name?: string
  details?: Record<string, unknown>
  ip_address?: string
  user_agent?: string
  created_at: string
}

interface APITokenUsageLog {
  id: string
  token_id: string
  token_name: string
  token_prefix: string
  username: string
  endpoint: string
  method: string
  status_code: number
  client_ip: string
  user_agent?: string
  response_time: number
  created_at: string
}

interface LogResponse<T> {
  logs: T[]
  total: number
  limit: number
  offset: number
}

const API_BASE = '/api/v1'

// Fetch functions
async function fetchAuditLogs(limit = 50, offset = 0, search?: string): Promise<LogResponse<AuditLog>> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  })
  if (search) params.set('search', search)

  const res = await fetch(`${API_BASE}/audit-logs?${params}`, {
    headers: getAuthHeaders(),
  })
  if (!res.ok) throw new Error('Failed to fetch audit logs')
  return res.json()
}

async function fetchAPITokenLogs(limit = 50, offset = 0): Promise<LogResponse<APITokenUsageLog>> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  })

  const res = await fetch(`${API_BASE}/audit-logs/api-tokens?${params}`, {
    headers: getAuthHeaders(),
  })
  if (!res.ok) throw new Error('Failed to fetch API token logs')
  return res.json()
}

// Helper functions
function formatTime(timestamp: string): string {
  return new Date(timestamp).toLocaleString()
}

function ActionBadge({ action }: { action: string }) {
  const colors: Record<string, string> = {
    created: 'bg-green-100 text-green-800',
    updated: 'bg-blue-100 text-blue-800',
    deleted: 'bg-red-100 text-red-800',
    login: 'bg-indigo-100 text-indigo-800',
    logout: 'bg-slate-100 text-slate-600',
    enabled: 'bg-teal-100 text-teal-800',
    disabled: 'bg-orange-100 text-orange-800',
    revoked: 'bg-yellow-100 text-yellow-800',
  }

  const getColor = () => {
    for (const [key, color] of Object.entries(colors)) {
      if (action.includes(key)) return color
    }
    return 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300'
  }

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${getColor()} transition-colors`}>
      {action}
    </span>
  )
}

function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: 'bg-green-100 text-green-800',
    POST: 'bg-blue-100 text-blue-800',
    PUT: 'bg-yellow-100 text-yellow-800',
    DELETE: 'bg-red-100 text-red-800',
    PATCH: 'bg-purple-100 text-purple-800',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[method] || 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300'} transition-colors`}>
      {method}
    </span>
  )
}

function StatusBadge({ status }: { status: number }) {
  const getColor = () => {
    if (status < 300) return 'bg-green-100 text-green-800'
    if (status < 400) return 'bg-yellow-100 text-yellow-800'
    return 'bg-red-100 text-red-800'
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${getColor()}`}>
      {status}
    </span>
  )
}

type TabType = 'admin' | 'api-token'

export default function AuditLog() {
  const { t } = useTranslation('logs')
  const [activeTab, setActiveTab] = useState<TabType>('admin')
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const limit = 30

  // Format relative time with translations
  const formatRelativeTime = (dateStr: string): string => {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffSec = Math.floor(diffMs / 1000)
    const diffMin = Math.floor(diffSec / 60)
    const diffHour = Math.floor(diffMin / 60)
    const diffDay = Math.floor(diffHour / 24)

    if (diffSec < 60) return t('audit.time.justNow')
    if (diffMin < 60) return t('audit.time.minutesAgo', { count: diffMin })
    if (diffHour < 24) return t('audit.time.hoursAgo', { count: diffHour })
    if (diffDay < 7) return t('audit.time.daysAgo', { count: diffDay })
    return formatTime(dateStr)
  }

  // Audit logs query
  const { data: auditData, isLoading: auditLoading } = useQuery({
    queryKey: ['audit-logs', offset, search],
    queryFn: () => fetchAuditLogs(limit, offset, search || undefined),
    enabled: activeTab === 'admin',
  })

  // API token logs query
  const { data: apiTokenData, isLoading: apiTokenLoading } = useQuery({
    queryKey: ['api-token-logs', offset],
    queryFn: () => fetchAPITokenLogs(limit, offset),
    enabled: activeTab === 'api-token',
  })

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab)
    setOffset(0)
  }

  const data = activeTab === 'admin' ? auditData : apiTokenData
  const isLoading = activeTab === 'admin' ? auditLoading : apiTokenLoading
  const totalPages = Math.ceil((data?.total || 0) / limit)
  const currentPage = Math.floor(offset / limit) + 1

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4 transition-colors">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('audit.stats.adminActivity')}</p>
          <p className="text-2xl font-bold text-slate-700 dark:text-white mt-1">
            {auditData?.total?.toLocaleString() || '0'}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4 transition-colors">
          <p className="text-xs font-medium text-blue-500 uppercase">{t('audit.stats.apiTokenUsage')}</p>
          <p className="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-1">
            {apiTokenData?.total?.toLocaleString() || '0'}
          </p>
        </div>
      </div>

      {/* Tabs and Filters */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4 transition-colors">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex gap-2">
            <button
              onClick={() => handleTabChange('admin')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === 'admin'
                ? 'bg-primary-500 text-white'
                : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600'
                }`}
            >
              {t('audit.tabs.admin')}
            </button>
            <button
              onClick={() => handleTabChange('api-token')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === 'api-token'
                ? 'bg-primary-500 text-white'
                : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600'
                }`}
            >
              {t('audit.tabs.apiToken')}
            </button>
          </div>

          {activeTab === 'admin' && (
            <input
              type="text"
              placeholder={t('audit.search.placeholder')}
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setOffset(0)
              }}
              className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 min-w-[250px] bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400"
            />
          )}
        </div>
      </div>

      {/* Content */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden transition-colors">
        {isLoading ? (
          <div className="p-8 text-center text-slate-500 dark:text-slate-400">{t('audit.loading')}</div>
        ) : (data?.logs?.length || 0) === 0 ? (
          <div className="p-8 text-center text-slate-500 dark:text-slate-400">
            {activeTab === 'admin' ? t('audit.empty.admin') : t('audit.empty.apiToken')}
          </div>
        ) : activeTab === 'admin' ? (
          /* Admin Activity Table */
          <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead className="bg-slate-50 dark:bg-slate-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.time')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.user')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.activity')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.target')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.ipAddress')}
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
              {auditData?.logs?.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <div className="text-sm text-slate-900 dark:text-white">{formatRelativeTime(log.created_at)}</div>
                    <div className="text-xs text-slate-500">{formatTime(log.created_at)}</div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-8 h-8 rounded-full bg-primary-500 flex items-center justify-center text-white text-sm font-medium">
                        {log.username.charAt(0).toUpperCase()}
                      </div>
                      <div className="ml-3">
                        <div className="text-sm font-medium text-slate-900 dark:text-white">{log.username}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-slate-900 dark:text-white font-medium">{log.action_label}</div>
                    <ActionBadge action={log.action} />
                  </td>
                  <td className="px-4 py-3">
                    {log.resource_name ? (
                      <div>
                        <div className="text-sm text-slate-900 dark:text-white">{log.resource_name}</div>
                        <div className="text-xs text-slate-500 dark:text-slate-400">
                          {log.resource_type}
                          {log.resource_id && ` • ${log.resource_id.slice(0, 8)}...`}
                        </div>
                      </div>
                    ) : log.resource_type ? (
                      <span className="text-sm text-slate-500 dark:text-slate-400">{log.resource_type}</span>
                    ) : (
                      <span className="text-slate-400 dark:text-slate-600">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-sm text-slate-600 dark:text-slate-400 font-mono">{log.ip_address || '-'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          /* API Token Usage Table */
          <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead className="bg-slate-50 dark:bg-slate-700/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.time')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.token')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.request')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.status')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.responseTime')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('audit.table.ip')}
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
              {apiTokenData?.logs?.map((log) => (
                <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <div className="text-sm text-slate-900 dark:text-white">{formatRelativeTime(log.created_at)}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">{formatTime(log.created_at)}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">{log.token_name}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      <code className="bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded font-mono text-slate-800 dark:text-slate-200">{log.token_prefix}...</code>
                      <span className="ml-1 text-slate-400">by {log.username}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <MethodBadge method={log.method} />
                      <span className="text-sm text-slate-700 dark:text-slate-300 font-mono">{log.endpoint}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <StatusBadge status={log.status_code} />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-sm text-slate-600 dark:text-slate-400">{log.response_time}ms</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="text-sm text-slate-600 dark:text-slate-400 font-mono">{log.client_ip}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4 transition-colors">
          <div className="flex items-center justify-between">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              {t('audit.pagination.total', { total: data?.total?.toLocaleString(), start: offset + 1, end: Math.min(offset + limit, data?.total || 0) })}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setOffset(Math.max(0, offset - limit))}
                disabled={offset === 0}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {t('audit.pagination.previous')}
              </button>
              <span className="text-sm text-slate-600 dark:text-slate-400">
                {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => setOffset(offset + limit)}
                disabled={currentPage >= totalPages}
                className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded-lg text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {t('audit.pagination.next')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

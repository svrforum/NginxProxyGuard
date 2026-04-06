import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getUpstream, updateUpstream, deleteUpstream, getUpstreamHealth } from '../../../api/security'
import type { CreateUpstreamRequest } from '../../../types/security'

interface ServerEntry {
  address: string
  port: number
  weight: number
  is_backup: boolean
}

interface UpstreamTabProps {
  hostId: string
}

export function UpstreamTabContent({ hostId }: UpstreamTabProps) {
  const { t } = useTranslation('proxyHost')
  const queryClient = useQueryClient()

  // Form state
  const [loadBalance, setLoadBalance] = useState<string>('round_robin')
  const [keepalive, setKeepalive] = useState<number>(32)
  const [servers, setServers] = useState<ServerEntry[]>([])
  const [healthCheckEnabled, setHealthCheckEnabled] = useState(false)
  const [healthCheckInterval, setHealthCheckInterval] = useState(30)
  const [healthCheckTimeout, setHealthCheckTimeout] = useState(5)
  const [healthCheckPath, setHealthCheckPath] = useState('/')
  const [healthCheckExpectedStatus, setHealthCheckExpectedStatus] = useState(200)

  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  // Fetch upstream config
  const { data: upstream, isLoading } = useQuery({
    queryKey: ['upstream', hostId],
    queryFn: () => getUpstream(hostId),
    retry: false,
  })

  // Fetch health status if upstream exists
  const { data: healthStatus } = useQuery({
    queryKey: ['upstream-health', upstream?.id],
    queryFn: () => getUpstreamHealth(upstream!.id),
    enabled: !!upstream?.id && upstream.health_check_enabled,
    retry: false,
  })

  // Sync form state from upstream data
  useEffect(() => {
    if (upstream) {
      setLoadBalance(upstream.load_balance || 'round_robin')
      setKeepalive(upstream.keepalive ?? 32)
      setServers(
        upstream.servers?.map((s) => ({
          address: s.address,
          port: s.port,
          weight: s.weight,
          is_backup: s.is_backup,
        })) || []
      )
      setHealthCheckEnabled(upstream.health_check_enabled)
      setHealthCheckInterval(upstream.health_check_interval || 30)
      setHealthCheckTimeout(upstream.health_check_timeout || 5)
      setHealthCheckPath(upstream.health_check_path || '/')
      setHealthCheckExpectedStatus(upstream.health_check_expected_status || 200)
    }
  }, [upstream])

  // Save mutation
  const saveMutation = useMutation({
    mutationFn: (data: CreateUpstreamRequest) => updateUpstream(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upstream', hostId] })
      setFeedback({ type: 'success', message: t('upstream.saveSuccess') })
      setTimeout(() => setFeedback(null), 3000)
    },
    onError: (err: Error) => {
      setFeedback({ type: 'error', message: `${t('upstream.saveError')}: ${err.message}` })
    },
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => deleteUpstream(hostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upstream', hostId] })
      setShowDeleteConfirm(false)
      setServers([])
      setFeedback({ type: 'success', message: t('upstream.saveSuccess') })
      setTimeout(() => setFeedback(null), 3000)
    },
    onError: (err: Error) => {
      setFeedback({ type: 'error', message: err.message })
    },
  })

  const handleSave = useCallback(() => {
    const data: CreateUpstreamRequest = {
      servers: servers.map((s) => ({
        address: s.address,
        port: s.port,
        weight: s.weight,
        is_backup: s.is_backup,
      })),
      load_balance: loadBalance,
      keepalive,
      health_check_enabled: healthCheckEnabled,
      health_check_interval: healthCheckInterval,
      health_check_timeout: healthCheckTimeout,
      health_check_path: healthCheckPath,
      health_check_expected_status: healthCheckExpectedStatus,
    }
    saveMutation.mutate(data)
  }, [servers, loadBalance, keepalive, healthCheckEnabled, healthCheckInterval, healthCheckTimeout, healthCheckPath, healthCheckExpectedStatus, saveMutation])

  const addServer = useCallback(() => {
    setServers((prev) => [...prev, { address: '', port: 80, weight: 1, is_backup: false }])
  }, [])

  const removeServer = useCallback((index: number) => {
    setServers((prev) => prev.filter((_, i) => i !== index))
  }, [])

  const updateServer = useCallback((index: number, field: keyof ServerEntry, value: string | number | boolean) => {
    setServers((prev) => prev.map((s, i) => (i === index ? { ...s, [field]: value } : s)))
  }, [])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <svg className="animate-spin w-6 h-6 text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Description */}
      <p className="text-sm text-slate-500 dark:text-slate-400">{t('upstream.description')}</p>

      {/* Feedback */}
      {feedback && (
        <div className={`p-3 rounded-lg text-sm ${
          feedback.type === 'success'
            ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'
        }`}>
          {feedback.message}
        </div>
      )}

      {/* Load Balance Method */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
          {t('upstream.loadBalance')}
        </label>
        <select
          value={loadBalance}
          onChange={(e) => setLoadBalance(e.target.value)}
          className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        >
          <option value="round_robin">{t('upstream.methods.roundRobin')}</option>
          <option value="least_conn">{t('upstream.methods.leastConn')}</option>
          <option value="ip_hash">{t('upstream.methods.ipHash')}</option>
          <option value="random">{t('upstream.methods.random')}</option>
        </select>
      </div>

      {/* Keepalive */}
      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
          {t('upstream.keepalive')}
        </label>
        <input
          type="number"
          min={0}
          value={keepalive}
          onChange={(e) => setKeepalive(parseInt(e.target.value) || 0)}
          className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        />
      </div>

      {/* Backend Servers */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
            {t('upstream.backendServers')}
          </label>
          <button
            type="button"
            onClick={addServer}
            className="text-sm font-medium text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 transition-colors"
          >
            + {t('upstream.addServer')}
          </button>
        </div>

        {servers.length === 0 ? (
          <div className="text-center py-8 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700">
            <p className="text-sm text-slate-500 dark:text-slate-400">{t('upstream.noServers')}</p>
          </div>
        ) : (
          <div className="space-y-3">
            {servers.map((server, index) => (
              <div key={index} className="flex items-center gap-2 p-3 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700">
                {/* Address */}
                <input
                  type="text"
                  value={server.address}
                  onChange={(e) => updateServer(index, 'address', e.target.value)}
                  placeholder={t('upstream.addressPlaceholder')}
                  className="flex-1 min-w-0 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                />
                {/* Port */}
                <div className="flex items-center gap-1">
                  <span className="text-xs text-slate-500 dark:text-slate-400">{t('upstream.port')}</span>
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    value={server.port}
                    onChange={(e) => updateServer(index, 'port', parseInt(e.target.value) || 80)}
                    className="w-20 px-2 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                  />
                </div>
                {/* Weight */}
                <div className="flex items-center gap-1">
                  <span className="text-xs text-slate-500 dark:text-slate-400">{t('upstream.weight')}</span>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={server.weight}
                    onChange={(e) => updateServer(index, 'weight', parseInt(e.target.value) || 1)}
                    className="w-16 px-2 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                  />
                </div>
                {/* Backup toggle */}
                <label className="flex items-center gap-1 cursor-pointer whitespace-nowrap">
                  <input
                    type="checkbox"
                    checked={server.is_backup}
                    onChange={(e) => updateServer(index, 'is_backup', e.target.checked)}
                    className="w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500"
                  />
                  <span className="text-xs text-slate-500 dark:text-slate-400">{t('upstream.backup')}</span>
                </label>
                {/* Remove */}
                <button
                  type="button"
                  onClick={() => removeServer(index)}
                  className="p-1.5 text-slate-400 hover:text-red-500 dark:hover:text-red-400 transition-colors"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Health Check */}
      <div className={`p-4 rounded-lg border-2 transition-colors ${
        healthCheckEnabled
          ? 'bg-emerald-50 border-emerald-200 dark:bg-emerald-900/20 dark:border-emerald-800'
          : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
      }`}>
        <label className="flex items-center justify-between cursor-pointer">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
              healthCheckEnabled ? 'bg-emerald-100 dark:bg-emerald-900/40' : 'bg-slate-200 dark:bg-slate-700'
            }`}>
              <svg className={`w-5 h-5 ${healthCheckEnabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
              </svg>
            </div>
            <div>
              <span className="text-sm font-medium text-slate-900 dark:text-white">
                {t('upstream.enableHealthCheck')}
              </span>
              <p className="text-xs text-amber-600 dark:text-amber-400">
                ({t('upstream.healthCheckNote')})
              </p>
            </div>
          </div>
          <input
            type="checkbox"
            checked={healthCheckEnabled}
            onChange={(e) => setHealthCheckEnabled(e.target.checked)}
            className="rounded border-slate-300 text-emerald-600 focus:ring-emerald-500 h-5 w-5"
          />
        </label>

        {healthCheckEnabled && (
          <div className="mt-4 space-y-4 bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  {t('upstream.checkInterval')}
                </label>
                <input
                  type="number"
                  min={5}
                  value={healthCheckInterval}
                  onChange={(e) => setHealthCheckInterval(parseInt(e.target.value) || 30)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                  {t('upstream.checkTimeout')}
                </label>
                <input
                  type="number"
                  min={1}
                  value={healthCheckTimeout}
                  onChange={(e) => setHealthCheckTimeout(parseInt(e.target.value) || 5)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {t('upstream.checkPath')}
              </label>
              <input
                type="text"
                value={healthCheckPath}
                onChange={(e) => setHealthCheckPath(e.target.value)}
                placeholder="/"
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                {t('upstream.expectedStatus')}
              </label>
              <input
                type="number"
                min={100}
                max={599}
                value={healthCheckExpectedStatus}
                onChange={(e) => setHealthCheckExpectedStatus(parseInt(e.target.value) || 200)}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
              />
            </div>
          </div>
        )}
      </div>

      {/* Health Status Display */}
      {healthStatus && (
        <div className="p-4 bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-2 mb-3">
            <div className={`w-3 h-3 rounded-full ${healthStatus.is_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {healthStatus.is_healthy ? t('upstream.healthy') : t('upstream.unhealthy')}
              {' - '}
              {healthStatus.healthy_count}/{healthStatus.servers?.length || 0} {t('upstream.serversUp')}
            </span>
          </div>
          {healthStatus.servers?.map((srv, i) => (
            <div key={i} className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400 py-1">
              <div className={`w-2 h-2 rounded-full ${srv.is_healthy ? 'bg-green-500' : 'bg-red-500'}`} />
              <span>{srv.address}:{srv.port}</span>
              {srv.is_backup && (
                <span className="px-1.5 py-0.5 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 rounded text-[10px]">
                  {t('upstream.backup')}
                </span>
              )}
              {srv.response_time_ms !== undefined && (
                <span className="text-slate-400">{srv.response_time_ms}ms</span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between pt-2">
        {upstream?.id ? (
          <button
            type="button"
            onClick={() => setShowDeleteConfirm(true)}
            className="text-sm font-medium text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 transition-colors"
          >
            {t('upstream.deleteUpstream')}
          </button>
        ) : (
          <div />
        )}
        <button
          type="button"
          onClick={handleSave}
          disabled={saveMutation.isPending}
          className="bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
        >
          {saveMutation.isPending && (
            <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
          )}
          {saveMutation.isPending ? t('upstream.saving') : t('upstream.saveUpstream')}
        </button>
      </div>

      {/* Delete Confirm Dialog */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 max-w-sm mx-4">
            <p className="text-sm text-slate-700 dark:text-slate-300 mb-4">
              {t('upstream.deleteConfirm')}
            </p>
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setShowDeleteConfirm(false)}
                className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                {t('common:buttons.cancel')}
              </button>
              <button
                type="button"
                onClick={() => deleteMutation.mutate()}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 disabled:bg-red-400 rounded-lg transition-colors"
              >
                {t('upstream.deleteUpstream')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

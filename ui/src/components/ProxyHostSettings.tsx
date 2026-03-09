import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ProxyHost } from '../types/proxy-host'
import type {
  CreateRateLimitRequest,
  CreateFail2banRequest,
  CreateSecurityHeadersRequest,
  CreateBotFilterRequest,
} from '../types/security'
import {
  getRateLimit,
  updateRateLimit,
  getFail2ban,
  updateFail2ban,
  getSecurityHeaders,
  updateSecurityHeaders,
  listBannedIPs,
  banIP,
  unbanIP,
  getBotFilter,
  updateBotFilter,
} from '../api/security'
import type { BannedIP } from '../types/security'

interface ProxyHostSettingsProps {
  host: ProxyHost
  onClose: () => void
}

type TabType = 'rate-limit' | 'fail2ban' | 'bot-filter' | 'security-headers' | 'banned-ips'

export function ProxyHostSettings({ host, onClose }: ProxyHostSettingsProps) {
  const [activeTab, setActiveTab] = useState<TabType>('rate-limit')
  const queryClient = useQueryClient()

  const tabs: { id: TabType; label: string; icon: JSX.Element }[] = [
    {
      id: 'rate-limit',
      label: 'Rate Limit',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      id: 'fail2ban',
      label: 'Fail2ban',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
    },
    {
      id: 'security-headers',
      label: 'Security Headers',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      id: 'banned-ips',
      label: 'Banned IPs',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
    },
  ]

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Advanced Settings</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">{host.domain_names.join(', ')}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-400 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="px-6 pt-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 border-b-2 border-primary-600'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-700'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
          {activeTab === 'rate-limit' && (
            <RateLimitSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'fail2ban' && (
            <Fail2banSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'bot-filter' && (
            <BotFilterSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'security-headers' && (
            <SecurityHeadersSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'banned-ips' && (
            <BannedIPsSettings hostId={host.id} queryClient={queryClient} />
          )}
        </div>
      </div>
    </div>
  )
}

// Rate Limit Settings Component
function RateLimitSettings({ hostId, queryClient }: { hostId: string; queryClient: ReturnType<typeof useQueryClient> }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['rate-limit', hostId],
    queryFn: () => getRateLimit(hostId),
    retry: false, // Don't retry on 404
  })

  const [formData, setFormData] = useState<CreateRateLimitRequest>({
    enabled: false,
    requests_per_second: 10,
    burst_size: 20,
    zone_size: '10m',
    limit_by: 'ip',
    limit_response: 429,
    whitelist_ips: '',
  })

  const [initialized, setInitialized] = useState(false)

  // Sync form data when API data loads
  useEffect(() => {
    if (data && !initialized) {
      setFormData({
        enabled: data.enabled,
        requests_per_second: data.requests_per_second,
        burst_size: data.burst_size,
        zone_size: data.zone_size,
        limit_by: data.limit_by,
        limit_response: data.limit_response,
        whitelist_ips: data.whitelist_ips || '',
      })
      setInitialized(true)
    } else if (error && !initialized) {
      // No existing config, use defaults but mark as initialized
      setInitialized(true)
    }
  }, [data, error, initialized])

  const mutation = useMutation({
    mutationFn: (data: CreateRateLimitRequest) => updateRateLimit(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rate-limit', hostId] })
      alert('Rate limit settings saved!')
    },
    onError: (err) => alert(`Error: ${err.message}`),
  })

  if (isLoading) return <div className="text-center py-8">Loading...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-medium text-slate-900 dark:text-white">Rate Limiting</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">Limit requests per second to prevent abuse</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.enabled}
            onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm font-medium">Enabled</span>
        </label>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Requests per Second</label>
          <input
            type="number"
            value={formData.requests_per_second}
            onChange={(e) => setFormData((prev) => ({ ...prev, requests_per_second: Number(e.target.value) }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:bg-slate-100 dark:disabled:bg-slate-600 disabled:text-slate-500 dark:disabled:text-slate-400"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Burst Size</label>
          <input
            type="number"
            value={formData.burst_size}
            onChange={(e) => setFormData((prev) => ({ ...prev, burst_size: Number(e.target.value) }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:bg-slate-100 dark:disabled:bg-slate-600 disabled:text-slate-500 dark:disabled:text-slate-400"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Limit By</label>
          <select
            value={formData.limit_by}
            onChange={(e) => setFormData((prev) => ({ ...prev, limit_by: e.target.value }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:bg-slate-100 dark:disabled:bg-slate-600 disabled:text-slate-500 dark:disabled:text-slate-400"
          >
            <option value="ip">IP Address</option>
            <option value="uri">URI</option>
            <option value="ip_uri">IP + URI</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Response Code</label>
          <select
            value={formData.limit_response}
            onChange={(e) => setFormData((prev) => ({ ...prev, limit_response: Number(e.target.value) }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:bg-slate-100 dark:disabled:bg-slate-600 disabled:text-slate-500 dark:disabled:text-slate-400"
          >
            <option value={429}>429 Too Many Requests</option>
            <option value={503}>503 Service Unavailable</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Whitelist IPs (comma separated)</label>
        <input
          type="text"
          value={formData.whitelist_ips}
          onChange={(e) => setFormData((prev) => ({ ...prev, whitelist_ips: e.target.value }))}
          placeholder="192.168.1.1, 10.0.0.0/8"
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:bg-slate-100 dark:disabled:bg-slate-600 disabled:text-slate-500 dark:disabled:text-slate-400"
        />
      </div>

      <button
        onClick={() => mutation.mutate(formData)}
        disabled={mutation.isPending}
        className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  )
}

// Fail2ban Settings Component
function Fail2banSettings({ hostId, queryClient }: { hostId: string; queryClient: ReturnType<typeof useQueryClient> }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['fail2ban', hostId],
    queryFn: () => getFail2ban(hostId),
    retry: false,
  })

  const [formData, setFormData] = useState<CreateFail2banRequest>({
    enabled: false,
    max_retries: 5,
    find_time: 600,
    ban_time: 3600,
    fail_codes: '401,403,404',
    action: 'block',
  })

  const [initialized, setInitialized] = useState(false)

  useEffect(() => {
    if (data && !initialized) {
      setFormData({
        enabled: data.enabled,
        max_retries: data.max_retries,
        find_time: data.find_time,
        ban_time: data.ban_time,
        fail_codes: data.fail_codes,
        action: data.action,
      })
      setInitialized(true)
    } else if (error && !initialized) {
      setInitialized(true)
    }
  }, [data, error, initialized])

  const mutation = useMutation({
    mutationFn: (data: CreateFail2banRequest) => updateFail2ban(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fail2ban', hostId] })
      alert('Fail2ban settings saved!')
    },
    onError: (err) => alert(`Error: ${err.message}`),
  })

  if (isLoading) return <div className="text-center py-8">Loading...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-medium text-slate-900 dark:text-white">Fail2ban</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">Auto-ban IPs after repeated failures</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.enabled}
            onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm font-medium">Enabled</span>
        </label>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Max Retries</label>
          <input
            type="number"
            value={formData.max_retries}
            onChange={(e) => setFormData((prev) => ({ ...prev, max_retries: Number(e.target.value) }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Failures before ban</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Find Time (seconds)</label>
          <input
            type="number"
            value={formData.find_time}
            onChange={(e) => setFormData((prev) => ({ ...prev, find_time: Number(e.target.value) }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Time window for counting failures</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Ban Time (seconds)</label>
          <input
            type="number"
            value={formData.ban_time}
            onChange={(e) => setFormData((prev) => ({ ...prev, ban_time: Number(e.target.value) }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Duration of ban (3600 = 1 hour)</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Action</label>
          <select
            value={formData.action}
            onChange={(e) => setFormData((prev) => ({ ...prev, action: e.target.value }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="block">Block</option>
            <option value="log">Log Only</option>
            <option value="notify">Notify</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Failure Status Codes (comma separated)</label>
        <input
          type="text"
          value={formData.fail_codes}
          onChange={(e) => setFormData((prev) => ({ ...prev, fail_codes: e.target.value }))}
          placeholder="401,403,404"
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        />
      </div>

      <button
        onClick={() => mutation.mutate(formData)}
        disabled={mutation.isPending}
        className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  )
}

// Bot Filter Settings Component
function BotFilterSettings({ hostId, queryClient }: { hostId: string; queryClient: ReturnType<typeof useQueryClient> }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['bot-filter', hostId],
    queryFn: () => getBotFilter(hostId),
    retry: false,
  })

  const [formData, setFormData] = useState<CreateBotFilterRequest>({
    enabled: false,
    block_bad_bots: true,
    block_ai_bots: false,
    allow_search_engines: true,
    custom_blocked_agents: '',
    custom_allowed_agents: '',
    challenge_suspicious: false,
  })

  const [initialized, setInitialized] = useState(false)

  useEffect(() => {
    if (data && !initialized) {
      setFormData({
        enabled: data.enabled,
        block_bad_bots: data.block_bad_bots,
        block_ai_bots: data.block_ai_bots,
        allow_search_engines: data.allow_search_engines,
        custom_blocked_agents: data.custom_blocked_agents || '',
        custom_allowed_agents: data.custom_allowed_agents || '',
        challenge_suspicious: data.challenge_suspicious,
      })
      setInitialized(true)
    } else if (error && !initialized) {
      setInitialized(true)
    }
  }, [data, error, initialized])

  const mutation = useMutation({
    mutationFn: (data: CreateBotFilterRequest) => updateBotFilter(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['bot-filter', hostId] })
      alert('Bot filter settings saved!')
    },
    onError: (err) => alert(`Error: ${err.message}`),
  })

  if (isLoading) return <div className="text-center py-8">Loading...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-medium text-slate-900 dark:text-white">Bot Filter</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">Block malicious bots and scrapers</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.enabled}
            onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm font-medium">Enabled</span>
        </label>
      </div>

      <div className="space-y-3">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.block_bad_bots}
            onChange={(e) => setFormData((prev) => ({ ...prev, block_bad_bots: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <div>
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Block Bad Bots</span>
            <p className="text-xs text-slate-500 dark:text-slate-400">Block known malicious bots and scrapers</p>
          </div>
        </label>

        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.block_ai_bots}
            onChange={(e) => setFormData((prev) => ({ ...prev, block_ai_bots: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <div>
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Block AI Bots</span>
            <p className="text-xs text-slate-500 dark:text-slate-400">Block AI crawlers (GPTBot, ChatGPT, Claude, etc.)</p>
          </div>
        </label>

        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.allow_search_engines}
            onChange={(e) => setFormData((prev) => ({ ...prev, allow_search_engines: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <div>
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Allow Search Engines</span>
            <p className="text-xs text-slate-500 dark:text-slate-400">Allow Googlebot, Bingbot, etc.</p>
          </div>
        </label>

        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.challenge_suspicious}
            onChange={(e) => setFormData((prev) => ({ ...prev, challenge_suspicious: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <div>
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Challenge Suspicious</span>
            <p className="text-xs text-slate-500 dark:text-slate-400">Show CAPTCHA for suspicious requests</p>
          </div>
        </label>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Custom Blocked User-Agents</label>
        <textarea
          value={formData.custom_blocked_agents}
          onChange={(e) => setFormData((prev) => ({ ...prev, custom_blocked_agents: e.target.value }))}
          placeholder="One per line"
          rows={3}
          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        />
      </div>

      <button
        onClick={() => mutation.mutate(formData)}
        disabled={mutation.isPending}
        className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  )
}

// Security Headers Settings Component
function SecurityHeadersSettings({ hostId, queryClient }: { hostId: string; queryClient: ReturnType<typeof useQueryClient> }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['security-headers', hostId],
    queryFn: () => getSecurityHeaders(hostId),
    retry: false,
  })

  const [formData, setFormData] = useState<CreateSecurityHeadersRequest>({
    enabled: false,
    hsts_enabled: true,
    hsts_max_age: 31536000,
    hsts_include_subdomains: true,
    hsts_preload: false,
    x_frame_options: 'SAMEORIGIN',
    x_content_type_options: true,
    x_xss_protection: true,
    referrer_policy: 'strict-origin-when-cross-origin',
    content_security_policy: '',
    permissions_policy: '',
  })

  const [initialized, setInitialized] = useState(false)

  useEffect(() => {
    if (data && !initialized) {
      setFormData({
        enabled: data.enabled,
        hsts_enabled: data.hsts_enabled,
        hsts_max_age: data.hsts_max_age,
        hsts_include_subdomains: data.hsts_include_subdomains,
        hsts_preload: data.hsts_preload,
        x_frame_options: data.x_frame_options,
        x_content_type_options: data.x_content_type_options,
        x_xss_protection: data.x_xss_protection,
        referrer_policy: data.referrer_policy,
        content_security_policy: data.content_security_policy || '',
        permissions_policy: data.permissions_policy || '',
      })
      setInitialized(true)
    } else if (error && !initialized) {
      setInitialized(true)
    }
  }, [data, error, initialized])

  const mutation = useMutation({
    mutationFn: (data: CreateSecurityHeadersRequest) => updateSecurityHeaders(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['security-headers', hostId] })
      alert('Security headers settings saved!')
    },
    onError: (err) => alert(`Error: ${err.message}`),
  })

  if (isLoading) return <div className="text-center py-8">Loading...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="font-medium text-slate-900 dark:text-white">Security Headers</h3>
          <p className="text-sm text-slate-500 dark:text-slate-400">HTTP security headers for browser protection</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.enabled}
            onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm font-medium">Enabled</span>
        </label>
      </div>

      {/* HSTS Settings */}
      <div className="p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg space-y-3">
        <h4 className="font-medium text-slate-800 dark:text-slate-200">HSTS (HTTP Strict Transport Security)</h4>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.hsts_enabled}
            onChange={(e) => setFormData((prev) => ({ ...prev, hsts_enabled: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm">Enable HSTS</span>
        </label>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">Max Age (seconds)</label>
            <input
              type="number"
              value={formData.hsts_max_age}
              onChange={(e) => setFormData((prev) => ({ ...prev, hsts_max_age: Number(e.target.value) }))}
              className="w-full px-2 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.hsts_include_subdomains}
              onChange={(e) => setFormData((prev) => ({ ...prev, hsts_include_subdomains: e.target.checked }))}
              className="rounded border-slate-300 text-primary-600"
            />
            <span className="text-xs">Include Subdomains</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.hsts_preload}
              onChange={(e) => setFormData((prev) => ({ ...prev, hsts_preload: e.target.checked }))}
              className="rounded border-slate-300 text-primary-600"
            />
            <span className="text-xs">Preload</span>
          </label>
        </div>
      </div>

      {/* Other Headers */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">X-Frame-Options</label>
          <select
            value={formData.x_frame_options}
            onChange={(e) => setFormData((prev) => ({ ...prev, x_frame_options: e.target.value }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="DENY">DENY</option>
            <option value="SAMEORIGIN">SAMEORIGIN</option>
            <option value="">None</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Referrer-Policy</label>
          <select
            value={formData.referrer_policy}
            onChange={(e) => setFormData((prev) => ({ ...prev, referrer_policy: e.target.value }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="no-referrer">no-referrer</option>
            <option value="no-referrer-when-downgrade">no-referrer-when-downgrade</option>
            <option value="origin">origin</option>
            <option value="origin-when-cross-origin">origin-when-cross-origin</option>
            <option value="same-origin">same-origin</option>
            <option value="strict-origin">strict-origin</option>
            <option value="strict-origin-when-cross-origin">strict-origin-when-cross-origin</option>
            <option value="unsafe-url">unsafe-url</option>
          </select>
        </div>
      </div>

      <div className="space-y-3">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.x_content_type_options}
            onChange={(e) => setFormData((prev) => ({ ...prev, x_content_type_options: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm">X-Content-Type-Options: nosniff</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={formData.x_xss_protection}
            onChange={(e) => setFormData((prev) => ({ ...prev, x_xss_protection: e.target.checked }))}
            className="rounded border-slate-300 text-primary-600"
          />
          <span className="text-sm">X-XSS-Protection: 1; mode=block</span>
        </label>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Content-Security-Policy</label>
        <textarea
          value={formData.content_security_policy}
          onChange={(e) => setFormData((prev) => ({ ...prev, content_security_policy: e.target.value }))}
          placeholder="default-src 'self'; script-src 'self' 'unsafe-inline'"
          rows={2}
          className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm dark:border-slate-600 dark:bg-slate-700 dark:text-white"
        />
      </div>

      <button
        onClick={() => mutation.mutate(formData)}
        disabled={mutation.isPending}
        className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  )
}

// Banned IPs Settings Component
function BannedIPsSettings({ hostId, queryClient }: { hostId: string; queryClient: ReturnType<typeof useQueryClient> }) {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['banned-ips', hostId],
    queryFn: () => listBannedIPs(hostId, 1, 100),
  })

  const [newIP, setNewIP] = useState('')
  const [reason, setReason] = useState('')
  const [banTime, setBanTime] = useState(3600)

  const banMutation = useMutation({
    mutationFn: () => banIP({ proxy_host_id: hostId, ip_address: newIP, reason, ban_time: banTime }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips', hostId] })
      setNewIP('')
      setReason('')
      alert('IP banned successfully!')
    },
    onError: (err) => alert(`Error: ${err.message}`),
  })

  const unbanMutation = useMutation({
    mutationFn: (id: string) => unbanIP(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips', hostId] })
      alert('IP unbanned successfully!')
    },
    onError: (err) => alert(`Error: ${err.message}`),
  })

  if (isLoading) return <div className="text-center py-8">Loading...</div>

  const bannedIPs = data?.data || []

  return (
    <div className="space-y-6">
      <div>
        <h3 className="font-medium text-slate-900 dark:text-white">Banned IPs</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">Manage manually banned IP addresses</p>
      </div>

      {/* Add new ban */}
      <div className="p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg space-y-4">
        <h4 className="font-medium text-slate-800 dark:text-slate-200">Ban New IP</h4>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">IP Address</label>
            <input
              type="text"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              placeholder="192.168.1.100"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Ban Duration</label>
            <select
              value={banTime}
              onChange={(e) => setBanTime(Number(e.target.value))}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value={3600}>1 Hour</option>
              <option value={86400}>1 Day</option>
              <option value={604800}>1 Week</option>
              <option value={2592000}>1 Month</option>
              <option value={0}>Permanent</option>
            </select>
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Reason (optional)</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Manual ban - suspicious activity"
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>
        <button
          onClick={() => banMutation.mutate()}
          disabled={!newIP || banMutation.isPending}
          className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
        >
          {banMutation.isPending ? 'Banning...' : 'Ban IP'}
        </button>
      </div>

      {/* Banned IPs list */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h4 className="font-medium text-slate-800 dark:text-slate-200">Currently Banned ({bannedIPs.length})</h4>
          <button
            onClick={() => refetch()}
            className="text-sm text-primary-600 hover:text-primary-700"
          >
            Refresh
          </button>
        </div>

        {bannedIPs.length === 0 ? (
          <div className="text-center py-8 text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
            No banned IPs
          </div>
        ) : (
          <div className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
              <thead className="bg-slate-50 dark:bg-slate-900">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400">IP Address</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400">Reason</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400">Expires</th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 dark:text-slate-400">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                {bannedIPs.map((ban: BannedIP) => (
                  <tr key={ban.id}>
                    <td className="px-4 py-2 text-sm font-mono">{ban.ip_address}</td>
                    <td className="px-4 py-2 text-sm text-slate-600 dark:text-slate-400">{ban.reason || '-'}</td>
                    <td className="px-4 py-2 text-sm text-slate-600 dark:text-slate-400">
                      {ban.is_permanent ? (
                        <span className="text-red-600 font-medium">Permanent</span>
                      ) : ban.expires_at ? (
                        new Date(ban.expires_at).toLocaleString()
                      ) : '-'}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => unbanMutation.mutate(ban.id)}
                        disabled={unbanMutation.isPending}
                        className="text-sm text-red-600 hover:text-red-700"
                      >
                        Unban
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

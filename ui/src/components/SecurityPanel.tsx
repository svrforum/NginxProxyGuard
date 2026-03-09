import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  getRateLimit, updateRateLimit,
  getFail2ban, updateFail2ban,
  getBotFilter, updateBotFilter, getKnownBots,
  getSecurityHeaders, updateSecurityHeaders, applySecurityHeaderPreset,
  listBannedIPs, banIP, unbanIP,
} from '../api/security';
import type {
  BanIPRequest,
  CreateRateLimitRequest,
  CreateFail2banRequest,
  CreateBotFilterRequest,
  CreateSecurityHeadersRequest,
} from '../types/security';

interface SecurityPanelProps {
  proxyHostId: string;
  onClose: () => void;
}

type ActiveTab = 'rate-limit' | 'fail2ban' | 'bot-filter' | 'headers' | 'banned-ips';

export default function SecurityPanel({ proxyHostId, onClose }: SecurityPanelProps) {
  const { t } = useTranslation('proxyHost');
  const [activeTab, setActiveTab] = useState<ActiveTab>('rate-limit');

  const tabs = [
    { id: 'rate-limit' as const, label: t('form.protection.rateLimit.title') },
    { id: 'fail2ban' as const, label: t('form.protection.fail2ban.title') },
    { id: 'bot-filter' as const, label: t('form.security.botFilter.title') },
    { id: 'headers' as const, label: t('form.protection.securityHeaders.title') },
    { id: 'banned-ips' as const, label: t('form.protection.bannedIPs.title') },
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden m-4">
        <div className="flex items-center justify-between p-4 border-b dark:border-slate-700">
          <h2 className="text-lg font-semibold dark:text-white">{t('form.tabs.security')}</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex border-b dark:border-slate-700">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 ${activeTab === tab.id
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="p-4 overflow-y-auto max-h-[calc(90vh-120px)]">
          {activeTab === 'rate-limit' && <RateLimitTab proxyHostId={proxyHostId} />}
          {activeTab === 'fail2ban' && <Fail2banTab proxyHostId={proxyHostId} />}
          {activeTab === 'bot-filter' && <BotFilterTab proxyHostId={proxyHostId} />}
          {activeTab === 'headers' && <SecurityHeadersTab proxyHostId={proxyHostId} />}
          {activeTab === 'banned-ips' && <BannedIPsTab proxyHostId={proxyHostId} />}
        </div>
      </div>
    </div>
  );
}

function RateLimitTab({ proxyHostId }: { proxyHostId: string }) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['rate-limit', proxyHostId],
    queryFn: () => getRateLimit(proxyHostId),
  });

  const mutation = useMutation({
    mutationFn: (data: CreateRateLimitRequest) => updateRateLimit(proxyHostId, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rate-limit', proxyHostId] }),
  });

  const [form, setForm] = useState({
    enabled: false,
    requests_per_second: 10,
    burst_size: 20,
    zone_size: '10m',
    limit_by: 'ip',
    limit_response: 429,
    whitelist_ips: '',
  });

  // Update form when data loads
  if (data && !form.enabled && data.enabled) {
    setForm({
      enabled: data.enabled,
      requests_per_second: data.requests_per_second,
      burst_size: data.burst_size,
      zone_size: data.zone_size,
      limit_by: data.limit_by,
      limit_response: data.limit_response,
      whitelist_ips: data.whitelist_ips || '',
    });
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(form);
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          className="rounded border-gray-300"
        />
        <span className="font-medium">{t('form.protection.rateLimit.enabled')}</span>
      </label>

      {form.enabled && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Requests per Second
              </label>
              <input
                type="number"
                value={form.requests_per_second}
                onChange={(e) => setForm({ ...form, requests_per_second: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={1}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Burst Size
              </label>
              <input
                type="number"
                value={form.burst_size}
                onChange={(e) => setForm({ ...form, burst_size: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={0}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Zone Size</label>
              <select
                value={form.zone_size}
                onChange={(e) => setForm({ ...form, zone_size: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="5m">5 MB</option>
                <option value="10m">10 MB</option>
                <option value="20m">20 MB</option>
                <option value="50m">50 MB</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Limit By</label>
              <select
                value={form.limit_by}
                onChange={(e) => setForm({ ...form, limit_by: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="ip">IP Address</option>
                <option value="uri">URI</option>
                <option value="ip_uri">IP + URI</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Response Code</label>
              <select
                value={form.limit_response}
                onChange={(e) => setForm({ ...form, limit_response: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value={429}>429 Too Many Requests</option>
                <option value={503}>503 Service Unavailable</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Whitelist IPs (CIDR, comma-separated)
            </label>
            <textarea
              value={form.whitelist_ips}
              onChange={(e) => setForm({ ...form, whitelist_ips: e.target.value })}
              className="w-full px-3 py-2 border rounded-md"
              rows={2}
              placeholder="192.168.1.0/24, 10.0.0.1"
            />
          </div>
        </>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save'}
      </button>
    </form>
  );
}

function Fail2banTab({ proxyHostId }: { proxyHostId: string }) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['fail2ban', proxyHostId],
    queryFn: () => getFail2ban(proxyHostId),
  });

  const mutation = useMutation({
    mutationFn: (data: CreateFail2banRequest) => updateFail2ban(proxyHostId, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['fail2ban', proxyHostId] }),
  });

  const [form, setForm] = useState({
    enabled: false,
    max_retries: 5,
    find_time: 600,
    ban_time: 3600,
    fail_codes: '401,403,404',
    action: 'block',
  });

  if (data && !form.enabled && data.enabled) {
    setForm({
      enabled: data.enabled,
      max_retries: data.max_retries,
      find_time: data.find_time,
      ban_time: data.ban_time,
      fail_codes: data.fail_codes,
      action: data.action,
    });
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(form);
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          className="rounded border-gray-300"
        />
        <span className="font-medium">{t('form.protection.fail2ban.enabled')}</span>
      </label>

      {form.enabled && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.fail2ban.maxRetries')}</label>
              <input
                type="number"
                value={form.max_retries}
                onChange={(e) => setForm({ ...form, max_retries: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={1}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.fail2ban.findTime')}</label>
              <input
                type="number"
                value={form.find_time}
                onChange={(e) => setForm({ ...form, find_time: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={60}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.fail2ban.banTime')}</label>
              <input
                type="number"
                value={form.ban_time}
                onChange={(e) => setForm({ ...form, ban_time: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={0}
              />
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">0 = permanent</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Fail Codes (comma-separated)
              </label>
              <input
                type="text"
                value={form.fail_codes}
                onChange={(e) => setForm({ ...form, fail_codes: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="401,403,404"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Action</label>
              <select
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="block">Block IP</option>
                <option value="log">Log Only</option>
                <option value="notify">Notify Only</option>
              </select>
            </div>
          </div>
        </>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save'}
      </button>
    </form>
  );
}

function BotFilterTab({ proxyHostId }: { proxyHostId: string }) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['bot-filter', proxyHostId],
    queryFn: () => getBotFilter(proxyHostId),
  });

  const { data: knownBots } = useQuery({
    queryKey: ['known-bots'],
    queryFn: getKnownBots,
  });

  const mutation = useMutation({
    mutationFn: (data: CreateBotFilterRequest) => updateBotFilter(proxyHostId, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['bot-filter', proxyHostId] }),
  });

  const [form, setForm] = useState({
    enabled: false,
    block_bad_bots: true,
    block_ai_bots: false,
    allow_search_engines: true,
    custom_blocked_agents: '',
    custom_allowed_agents: '',
    challenge_suspicious: false,
  });

  if (data && !form.enabled && data.enabled) {
    setForm({
      enabled: data.enabled,
      block_bad_bots: data.block_bad_bots,
      block_ai_bots: data.block_ai_bots,
      allow_search_engines: data.allow_search_engines,
      custom_blocked_agents: data.custom_blocked_agents || '',
      custom_allowed_agents: data.custom_allowed_agents || '',
      challenge_suspicious: data.challenge_suspicious,
    });
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(form);
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          className="rounded border-gray-300"
        />
        <span className="font-medium">{t('form.security.botFilter.enabled')}</span>
      </label>

      {form.enabled && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.block_bad_bots}
                onChange={(e) => setForm({ ...form, block_bad_bots: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm">{t('form.security.botFilter.blockBadBots')}</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.block_ai_bots}
                onChange={(e) => setForm({ ...form, block_ai_bots: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm">{t('form.security.botFilter.blockAiBots')}</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.allow_search_engines}
                onChange={(e) => setForm({ ...form, allow_search_engines: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm">{t('form.security.botFilter.allowSearchEngines')}</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.challenge_suspicious}
                onChange={(e) => setForm({ ...form, challenge_suspicious: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm">{t('form.security.botFilter.challengeSuspicious')}</span>
            </label>
          </div>

          {knownBots && (
            <div className="grid grid-cols-3 gap-4 p-3 bg-gray-50 dark:bg-slate-700/50 rounded-md text-xs">
              <div>
                <p className="font-medium text-gray-700 dark:text-gray-300 mb-1">Bad Bots ({knownBots.bad_bots.length})</p>
                <p className="text-gray-500 dark:text-gray-400 truncate">{knownBots.bad_bots.slice(0, 5).join(', ')}...</p>
              </div>
              <div>
                <p className="font-medium text-gray-700 dark:text-gray-300 mb-1">AI Bots ({knownBots.ai_bots.length})</p>
                <p className="text-gray-500 dark:text-gray-400 truncate">{knownBots.ai_bots.slice(0, 5).join(', ')}...</p>
              </div>
              <div>
                <p className="font-medium text-gray-700 dark:text-gray-300 mb-1">Search Engines ({knownBots.search_engine_bots.length})</p>
                <p className="text-gray-500 dark:text-gray-400 truncate">{knownBots.search_engine_bots.slice(0, 5).join(', ')}...</p>
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Custom Blocked User-Agents (one per line)
            </label>
            <textarea
              value={form.custom_blocked_agents}
              onChange={(e) => setForm({ ...form, custom_blocked_agents: e.target.value })}
              className="w-full px-3 py-2 border rounded-md text-sm"
              rows={3}
              placeholder="BadBot&#10;MaliciousCrawler"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Custom Allowed User-Agents (one per line)
            </label>
            <textarea
              value={form.custom_allowed_agents}
              onChange={(e) => setForm({ ...form, custom_allowed_agents: e.target.value })}
              className="w-full px-3 py-2 border rounded-md text-sm"
              rows={3}
              placeholder="MyInternalBot&#10;MonitoringService"
            />
          </div>
        </>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save'}
      </button>
    </form>
  );
}

function SecurityHeadersTab({ proxyHostId }: { proxyHostId: string }) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['security-headers', proxyHostId],
    queryFn: () => getSecurityHeaders(proxyHostId),
  });

  const mutation = useMutation({
    mutationFn: (data: CreateSecurityHeadersRequest) => updateSecurityHeaders(proxyHostId, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['security-headers', proxyHostId] }),
  });

  const presetMutation = useMutation({
    mutationFn: (preset: string) => applySecurityHeaderPreset(proxyHostId, preset),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['security-headers', proxyHostId] }),
  });

  const [form, setForm] = useState({
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
  });

  if (data && !form.enabled && data.enabled) {
    setForm({
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
    });
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(form);
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="flex items-center justify-between">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            className="rounded border-gray-300"
          />
          <span className="font-medium">{t('form.protection.securityHeaders.enabled')}</span>
        </label>

        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => presetMutation.mutate('strict')}
            className="px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200"
          >
            {t('form.protection.securityHeaders.preset.strict')}
          </button>
          <button
            type="button"
            onClick={() => presetMutation.mutate('moderate')}
            className="px-2 py-1 text-xs bg-yellow-100 text-yellow-700 rounded hover:bg-yellow-200"
          >
            {t('form.protection.securityHeaders.preset.moderate')}
          </button>
          <button
            type="button"
            onClick={() => presetMutation.mutate('relaxed')}
            className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded hover:bg-green-200"
          >
            {t('form.protection.securityHeaders.preset.relaxed')}
          </button>
        </div>
      </div>

      {form.enabled && (
        <>
          <div className="border dark:border-slate-700 rounded-md p-3 space-y-3">
            <h4 className="font-medium text-sm">{t('form.protection.securityHeaders.hsts')}</h4>
            <div className="grid grid-cols-4 gap-3">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.hsts_enabled}
                  onChange={(e) => setForm({ ...form, hsts_enabled: e.target.checked })}
                  className="rounded border-gray-300"
                />
                <span className="text-sm">{t('form.protection.securityHeaders.hstsEnabled')}</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.hsts_include_subdomains}
                  onChange={(e) => setForm({ ...form, hsts_include_subdomains: e.target.checked })}
                  className="rounded border-gray-300"
                />
                <span className="text-sm">{t('form.protection.securityHeaders.includeSubdomains')}</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.hsts_preload}
                  onChange={(e) => setForm({ ...form, hsts_preload: e.target.checked })}
                  className="rounded border-gray-300"
                />
                <span className="text-sm">{t('form.protection.securityHeaders.preload')}</span>
              </label>
              <div>
                <select
                  value={form.hsts_max_age}
                  onChange={(e) => setForm({ ...form, hsts_max_age: parseInt(e.target.value) })}
                  className="w-full px-2 py-1 text-sm border rounded"
                >
                  <option value={86400}>{t('form.protection.securityHeaders.maxAge.1day')}</option>
                  <option value={604800}>{t('form.protection.securityHeaders.maxAge.1week')}</option>
                  <option value={2592000}>{t('form.protection.securityHeaders.maxAge.30days')}</option>
                  <option value={31536000}>{t('form.protection.securityHeaders.maxAge.1year')}</option>
                </select>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.securityHeaders.xFrameOptions')}</label>
              <select
                value={form.x_frame_options}
                onChange={(e) => setForm({ ...form, x_frame_options: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="DENY">DENY</option>
                <option value="SAMEORIGIN">SAMEORIGIN</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.securityHeaders.referrerPolicy')}</label>
              <select
                value={form.referrer_policy}
                onChange={(e) => setForm({ ...form, referrer_policy: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="no-referrer">no-referrer</option>
                <option value="no-referrer-when-downgrade">no-referrer-when-downgrade</option>
                <option value="origin">origin</option>
                <option value="origin-when-cross-origin">origin-when-cross-origin</option>
                <option value="same-origin">same-origin</option>
                <option value="strict-origin">strict-origin</option>
                <option value="strict-origin-when-cross-origin">strict-origin-when-cross-origin</option>
              </select>
            </div>
          </div>

          <div className="flex gap-4">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.x_content_type_options}
                onChange={(e) => setForm({ ...form, x_content_type_options: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm">{t('form.protection.securityHeaders.xContentType')}</span>
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.x_xss_protection}
                onChange={(e) => setForm({ ...form, x_xss_protection: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="text-sm">{t('form.protection.securityHeaders.xssProtection')}</span>
            </label>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {t('form.protection.securityHeaders.csp')}
            </label>
            <textarea
              value={form.content_security_policy}
              onChange={(e) => setForm({ ...form, content_security_policy: e.target.value })}
              className="w-full px-3 py-2 border rounded-md text-sm font-mono"
              rows={3}
              placeholder="default-src 'self'; script-src 'self' 'unsafe-inline';"
            />
          </div>
        </>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
      >
        {mutation.isPending ? t('common:status.saving') : t('common:buttons.save')}
      </button>
    </form>
  );
}

function BannedIPsTab({ proxyHostId }: { proxyHostId: string }) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const [newIP, setNewIP] = useState('');
  const [reason, setReason] = useState('');
  const [banTime, setBanTime] = useState(3600);

  const { data, isLoading } = useQuery({
    queryKey: ['banned-ips', proxyHostId],
    queryFn: () => listBannedIPs(proxyHostId),
  });

  const banMutation = useMutation({
    mutationFn: (req: BanIPRequest) => banIP(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] });
      setNewIP('');
      setReason('');
    },
  });

  const unbanMutation = useMutation({
    mutationFn: unbanIP,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['banned-ips'] }),
  });

  const handleBan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIP) return;
    banMutation.mutate({
      proxy_host_id: proxyHostId,
      ip_address: newIP,
      reason,
      ban_time: banTime,
    });
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <div className="space-y-4">
      <form onSubmit={handleBan} className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.bannedIPs.ip')}</label>
          <input
            type="text"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="192.168.1.100"
          />
        </div>
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.bannedIPs.reason')}</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Manual ban"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.bannedIPs.duration')}</label>
          <select
            value={banTime}
            onChange={(e) => setBanTime(parseInt(e.target.value))}
            className="px-3 py-2 border rounded-md"
          >
            <option value={3600}>{t('form.protection.bannedIPs.durationOptions.1hour')}</option>
            <option value={86400}>{t('form.protection.bannedIPs.durationOptions.1day')}</option>
            <option value={604800}>{t('form.protection.bannedIPs.durationOptions.1week')}</option>
            <option value={0}>{t('form.protection.bannedIPs.durationOptions.permanent')}</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={banMutation.isPending}
          className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
        >
          {banMutation.isPending ? t('form.protection.bannedIPs.banning') : t('form.protection.bannedIPs.ban')}
        </button>
      </form>

      <div className="border dark:border-slate-700 rounded-md overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-700">
          <thead className="bg-gray-50 dark:bg-slate-900">
            <tr>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.ip')}</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.reason')}</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.bannedAt')}</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.expiresAt')}</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  {t('form.protection.bannedIPs.empty')}
                </td>
              </tr>
            ) : (
              data?.data?.map((ip) => (
                <tr key={ip.id}>
                  <td className="px-4 py-2 text-sm font-mono">{ip.ip_address}</td>
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">{ip.reason || '-'}</td>
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">
                    {new Date(ip.banned_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-sm">
                    {ip.is_permanent ? (
                      <span className="text-red-600 font-medium">{t('form.protection.bannedIPs.permanent')}</span>
                    ) : ip.expires_at ? (
                      new Date(ip.expires_at).toLocaleString()
                    ) : '-'}
                  </td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => unbanMutation.mutate(ip.id)}
                      disabled={unbanMutation.isPending}
                      className="text-sm text-indigo-600 hover:text-indigo-800"
                    >
                      {t('form.protection.bannedIPs.unban')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

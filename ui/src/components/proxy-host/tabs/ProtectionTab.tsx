import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { HelpTip } from '../../common/HelpTip'

// Debounce hook for auto-save
function useDebouncedSave<T>(
  data: T,
  saveFn: (data: T) => void,
  delay: number,
  enabled: boolean
) {
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const initializedRef = useRef(false)
  const prevDataRef = useRef<string>('')

  useEffect(() => {
    if (!enabled) return

    const currentData = JSON.stringify(data)

    // Skip initial render
    if (!initializedRef.current) {
      initializedRef.current = true
      prevDataRef.current = currentData
      return
    }

    // Skip if data hasn't changed
    if (currentData === prevDataRef.current) return
    prevDataRef.current = currentData

    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }

    timeoutRef.current = setTimeout(() => {
      saveFn(data)
    }, delay)

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [data, saveFn, delay, enabled])
}
import type {
  CreateRateLimitRequest,
  CreateSecurityHeadersRequest,
} from '../../../types/security'
import {
  getRateLimit,
  updateRateLimit,
  getSecurityHeaders,
  updateSecurityHeaders,
} from '../../../api/security'

interface ProtectionTabProps {
  hostId: string
}

export function ProtectionTabContent({ hostId }: ProtectionTabProps) {
  const { t } = useTranslation(['proxyHost', 'common'])

  return (
    <div className="space-y-6">
      {/* Security Headers Section - Most important, placed at top */}
      <SecurityHeadersSection hostId={hostId} />

      {/* Rate Limit Section */}
      <RateLimitSection hostId={hostId} />

      {/* Fail2ban Link - Settings moved to WAF menu */}
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg overflow-hidden transition-colors">
        <Link
          to="/waf/fail2ban"
          className="w-full px-4 py-4 flex items-center justify-between hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
              <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
            <div className="text-left">
              <div className="font-medium text-slate-900 dark:text-white">{t('form.protection.fail2ban.title')}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">{t('form.protection.fail2ban.linkDescription', 'Manage Fail2ban settings in WAF menu')}</div>
            </div>
          </div>
          <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </Link>
      </div>

      {/* Banned IPs Link */}
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg overflow-hidden transition-colors">
        <Link
          to="/waf/banned-ips"
          className="w-full px-4 py-4 flex items-center justify-between hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center">
              <svg className="w-5 h-5 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
            <div className="text-left">
              <div className="font-medium text-slate-900 dark:text-white">{t('form.protection.bannedIPs.title', '차단된 IP 관리')}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">{t('form.protection.bannedIPs.description', '중앙에서 차단된 IP를 관리합니다')}</div>
            </div>
          </div>
          <svg className="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </Link>
      </div>
    </div>
  )
}

// Security Headers Section
function SecurityHeadersSection({ hostId }: { hostId: string }) {
  const { t } = useTranslation(['proxyHost', 'common'])
  const queryClient = useQueryClient()
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
    },
    onError: (err) => console.error('Failed to save security headers:', err),
  })

  const handleSave = useCallback((data: CreateSecurityHeadersRequest) => {
    mutation.mutate(data)
  }, [mutation])

  useDebouncedSave(formData, handleSave, 1000, initialized)

  if (isLoading) return <div className="text-center py-4 text-sm text-slate-500 dark:text-slate-400">{t('common:status.loading')}</div>

  return (
    <div className={`p-4 rounded-lg border-2 transition-colors ${formData.enabled ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'}`}>
      <label className="flex items-center justify-between cursor-pointer">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.enabled ? 'bg-blue-100 dark:bg-blue-900/40' : 'bg-slate-200 dark:bg-slate-700'}`}>
            <svg className={`w-5 h-5 ${formData.enabled ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                {t('form.protection.securityHeaders.title')}
                <HelpTip contentKey="help.protection.securityHeaders" />
              </span>
              <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-300 text-xs font-medium rounded-full">{t('common:misc.recommended')}</span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.protection.securityHeaders.description')}</p>
          </div>
        </div>
        <input
          type="checkbox"
          checked={formData.enabled}
          onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
          className="rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 h-5 w-5 dark:bg-slate-700"
        />
      </label>

      {formData.enabled && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-blue-200 dark:border-blue-800 space-y-4">
          {/* HSTS Settings */}
          <div className="p-3 bg-white dark:bg-slate-800 rounded-lg space-y-2">
            <div className="flex items-center gap-1">
              <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{t('form.protection.securityHeaders.hsts')}</span>
              <HelpTip contentKey="help.protection.securityHeadersDetail.hsts" />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.hsts_enabled}
                  onChange={(e) => setFormData((prev) => ({ ...prev, hsts_enabled: e.target.checked }))}
                  className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
                />
                <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.hstsEnabled')}</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.hsts_include_subdomains}
                  onChange={(e) => setFormData((prev) => ({ ...prev, hsts_include_subdomains: e.target.checked }))}
                  className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
                />
                <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.includeSubdomains')}</span>
                <HelpTip contentKey="help.protection.securityHeadersDetail.includeSubdomains" />
              </label>
            </div>
          </div>

          {/* X-Frame-Options and Referrer Policy */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="flex items-center gap-1 text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
                {t('form.protection.securityHeaders.xFrameOptions')}
                <HelpTip contentKey="help.protection.securityHeadersDetail.xFrameOptions" />
              </label>
              <select
                value={formData.x_frame_options}
                onChange={(e) => setFormData((prev) => ({ ...prev, x_frame_options: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
              >
                <option value="DENY">DENY</option>
                <option value="SAMEORIGIN">SAMEORIGIN</option>
                <option value="">{t('common:misc.none')}</option>
              </select>
            </div>
            <div>
              <label className="flex items-center gap-1 text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
                {t('form.protection.securityHeaders.referrerPolicy')}
                <HelpTip contentKey="help.protection.securityHeadersDetail.referrerPolicy" />
              </label>
              <select
                value={formData.referrer_policy}
                onChange={(e) => setFormData((prev) => ({ ...prev, referrer_policy: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
              >
                <option value="no-referrer">no-referrer</option>
                <option value="strict-origin">strict-origin</option>
                <option value="strict-origin-when-cross-origin">strict-origin-when-cross-origin</option>
              </select>
            </div>
          </div>

          {/* Additional Checkboxes */}
          <div className="space-y-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.x_content_type_options}
                onChange={(e) => setFormData((prev) => ({ ...prev, x_content_type_options: e.target.checked }))}
                className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
              />
              <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.xContentType')}</span>
              <HelpTip contentKey="help.protection.securityHeadersDetail.xContentType" />
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.x_xss_protection}
                onChange={(e) => setFormData((prev) => ({ ...prev, x_xss_protection: e.target.checked }))}
                className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
              />
              <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.xssProtection')}</span>
              <HelpTip contentKey="help.protection.securityHeadersDetail.xssProtection" />
            </label>
          </div>

          {/* Advanced Headers Notice */}
          <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
            <div className="flex items-start gap-2">
              <svg className="w-4 h-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <p className="text-xs font-medium text-amber-800 dark:text-amber-300">{t('form.protection.securityHeaders.advancedHeadersTitle')}</p>
                <p className="text-xs text-amber-700 dark:text-amber-400 mt-1">{t('form.protection.securityHeaders.advancedHeadersDesc')}</p>
              </div>
            </div>
          </div>

          {mutation.isPending && (
            <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1">
              <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {t('common:status.saving')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Rate Limit Section
function RateLimitSection({ hostId }: { hostId: string }) {
  const { t } = useTranslation(['proxyHost', 'common'])
  const queryClient = useQueryClient()
  const { data, isLoading, error } = useQuery({
    queryKey: ['rate-limit', hostId],
    queryFn: () => getRateLimit(hostId),
    retry: false,
  })

  const [formData, setFormData] = useState<CreateRateLimitRequest>({
    enabled: false,
    requests_per_second: 50,
    burst_size: 100,
    zone_size: '10m',
    limit_by: 'ip',
    limit_response: 429,
    whitelist_ips: '',
  })

  const [initialized, setInitialized] = useState(false)

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
      setInitialized(true)
    }
  }, [data, error, initialized])

  const mutation = useMutation({
    mutationFn: (data: CreateRateLimitRequest) => updateRateLimit(hostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rate-limit', hostId] })
    },
    onError: (err) => console.error('Failed to save rate limit:', err),
  })

  const handleSave = useCallback((data: CreateRateLimitRequest) => {
    mutation.mutate(data)
  }, [mutation])

  useDebouncedSave(formData, handleSave, 1000, initialized)

  if (isLoading) return <div className="text-center py-4 text-sm text-slate-500">{t('common:status.loading')}</div>

  return (
    <div className={`p-4 rounded-lg border-2 transition-colors ${formData.enabled ? 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'}`}>
      <label className="flex items-center justify-between cursor-pointer">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.enabled ? 'bg-amber-100 dark:bg-amber-900/40' : 'bg-slate-200 dark:bg-slate-700'}`}>
            <svg className={`w-5 h-5 ${formData.enabled ? 'text-amber-600 dark:text-amber-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                {t('form.protection.rateLimit.title')}
                <HelpTip contentKey="help.protection.rateLimit" />
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.protection.rateLimit.description')}</p>
          </div>
        </div>
        <input
          type="checkbox"
          checked={formData.enabled}
          onChange={(e) => setFormData((prev) => ({ ...prev, enabled: e.target.checked }))}
          className="rounded border-slate-300 dark:border-slate-600 text-amber-600 focus:ring-amber-500 h-5 w-5 dark:bg-slate-700"
        />
      </label>

      {formData.enabled && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-amber-200 dark:border-amber-800 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.requestsPerSecond')}</label>
              <input
                type="number"
                value={formData.requests_per_second}
                onChange={(e) => setFormData((prev) => ({ ...prev, requests_per_second: Number(e.target.value) }))}
                className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.burst')}</label>
              <input
                type="number"
                value={formData.burst_size}
                onChange={(e) => setFormData((prev) => ({ ...prev, burst_size: Number(e.target.value) }))}
                className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.limitBy')}</label>
              <select
                value={formData.limit_by}
                onChange={(e) => setFormData((prev) => ({ ...prev, limit_by: e.target.value }))}
                className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
              >
                <option value="ip">{t('form.protection.rateLimit.limitByOptions.ip')}</option>
                <option value="uri">{t('form.protection.rateLimit.limitByOptions.uri')}</option>
                <option value="ip_uri">{t('form.protection.rateLimit.limitByOptions.ipUri')}</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.responseCode')}</label>
              <select
                value={formData.limit_response}
                onChange={(e) => setFormData((prev) => ({ ...prev, limit_response: Number(e.target.value) }))}
                className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
              >
                <option value={429}>429 Too Many Requests</option>
                <option value={503}>503 Service Unavailable</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.whitelistIPs')}</label>
            <input
              type="text"
              value={formData.whitelist_ips}
              onChange={(e) => setFormData((prev) => ({ ...prev, whitelist_ips: e.target.value }))}
              placeholder="192.168.1.1, 10.0.0.0/8"
              className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
            />
          </div>

          {mutation.isPending && (
            <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1">
              <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              {t('common:status.saving')}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

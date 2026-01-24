import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { fetchProxyHosts, deleteProxyHost, testProxyHost, updateProxyHost, testProxyHostConfig } from '../api/proxy-hosts'
import { HelpTip } from './common/HelpTip'
import { useEscapeKey } from '../hooks/useEscapeKey'
import type { ProxyHost, ProxyHostTestResult } from '../types/proxy-host'

interface ProxyHostListProps {
  onEdit: (host: ProxyHost, tab?: 'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection') => void
  onAdd: () => void
}

interface HealthStatus {
  [hostId: string]: 'checking' | 'online' | 'offline' | 'unknown'
}

// Test Result Modal Component
function TestResultModal({
  host,
  result,
  isLoading,
  error,
  onClose,
  onRetest
}: {
  host: ProxyHost
  result: ProxyHostTestResult | null
  isLoading: boolean
  error: string | null
  onClose: () => void
  onRetest: () => void
}) {
  const { t } = useTranslation('proxyHost')
  const [activeTab, setActiveTab] = useState<'summary' | 'ssl' | 'http' | 'cache' | 'security' | 'headers'>('summary')

  useEscapeKey(onClose)

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('test.title')}</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">{host.domain_names[0]}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onRetest}
              disabled={isLoading}
              className="px-3 py-1.5 text-sm font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 rounded-lg flex items-center gap-1.5"
            >
              <svg className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {t('test.retest')}
            </button>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="flex-1 flex items-center justify-center py-20">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4" />
              <p className="text-slate-600">{t('test.testing')}</p>
            </div>
          </div>
        )}

        {/* Error State */}
        {error && !isLoading && (
          <div className="flex-1 flex items-center justify-center py-20">
            <div className="text-center">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-red-600 font-medium mb-2">{t('test.failed')}</p>
              <p className="text-slate-500 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Result Content */}
        {result && !isLoading && (
          <>
            {/* Tabs */}
            <div className="px-6 border-b border-slate-200 dark:border-slate-700">
              <nav className="flex gap-1 -mb-px">
                {[
                  { id: 'summary', label: t('test.tabs.summary') },
                  { id: 'ssl', label: t('test.tabs.ssl') },
                  { id: 'http', label: t('test.tabs.http') },
                  { id: 'cache', label: t('test.tabs.cache') },
                  { id: 'security', label: t('test.tabs.security') },
                  { id: 'headers', label: t('test.tabs.headers') },
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${activeTab === tab.id
                      ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                      : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                      }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-auto p-6">
              {activeTab === 'summary' && <SummaryTab result={result} host={host} />}
              {activeTab === 'ssl' && <SSLTab result={result} />}
              {activeTab === 'http' && <HTTPTab result={result} host={host} />}
              {activeTab === 'cache' && <CacheTab result={result} host={host} />}
              {activeTab === 'security' && <SecurityTab result={result} />}
              {activeTab === 'headers' && <HeadersTab result={result} />}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

// Summary Tab
function SummaryTab({ result, host }: { result: ProxyHostTestResult; host: ProxyHost }) {
  const { t } = useTranslation('proxyHost')
  return (
    <div className="space-y-6">
      {/* Overall Status */}
      <div className={`p-4 rounded-lg ${result.success
        ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800'
        : 'bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800'}`}>
        <div className="flex items-center gap-3">
          {result.success ? (
            <div className="w-10 h-10 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
          ) : (
            <div className="w-10 h-10 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center">
              <svg className="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </div>
          )}
          <div>
            <h3 className={`font-semibold ${result.success ? 'text-green-800 dark:text-green-300' : 'text-red-800 dark:text-red-300'}`}>
              {result.success ? t('test.passed') : t('test.failed')}
            </h3>
            <p className={`text-sm ${result.success ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
              {result.error || `${t('test.responseTime')}: ${result.response_time_ms}ms • ${t('test.statusCode')}: ${result.status_code}`}
            </p>
          </div>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label={t('test.responseTime')}
          value={`${result.response_time_ms}ms`}
          status={result.response_time_ms < 500 ? 'good' : result.response_time_ms < 2000 ? 'warning' : 'bad'}
          help={t('test.help.responseTime')}
        />
        <StatCard
          label={t('test.statusCode')}
          value={result.status_code?.toString() || 'N/A'}
          status={result.status_code && result.status_code < 400 ? 'good' : 'bad'}
          help={t('test.help.statusCode')}
        />
        <StatCard
          label={t('test.protocol')}
          value={result.http?.protocol || 'N/A'}
          status={result.http?.http2_enabled ? 'good' : 'warning'}
          help={t('test.help.protocol')}
        />
        <StatCard
          label={t('test.ssl')}
          value={result.ssl?.enabled ? (result.ssl.valid ? t('test.valid') : t('test.invalid')) : t('test.disabled')}
          status={result.ssl?.enabled ? (result.ssl.valid ? 'good' : 'bad') : 'neutral'}
          help={t('test.help.ssl')}
        />
      </div>

      {/* Feature Check */}
      <div>
        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">{t('test.featureVerification')}</h4>
        <div className="grid grid-cols-2 gap-2">
          <FeatureCheck label={t('test.tabs.ssl')} configured={host.ssl_enabled} detected={result.ssl?.enabled} />
          <FeatureCheck label="HTTP/2" configured={host.ssl_http2} detected={result.http?.http2_enabled} />
          <FeatureCheck label="HTTP/3 (QUIC)" configured={host.ssl_http3} detected={result.http?.http3_enabled} />
          <FeatureCheck label={t('test.tabs.cache')} configured={host.cache_enabled} detected={!!result.cache?.cache_status} />
          <FeatureCheck label="HSTS" configured={true} detected={result.security?.hsts} />
          <FeatureCheck label="X-Frame-Options" configured={true} detected={!!result.security?.x_frame_options} />
        </div>
      </div>

      {/* Test Time */}
      <div className="text-xs text-slate-400 text-right">
        {t('test.testedAt')}: {new Date(result.tested_at).toLocaleString()}
      </div>
    </div>
  )
}

function StatCard({ label, value, status, help }: { label: string; value: string; status: 'good' | 'warning' | 'bad' | 'neutral', help?: string }) {
  const colors = {
    good: 'bg-green-50 border-green-200 text-green-700 dark:bg-green-900/20 dark:border-green-900/50 dark:text-green-400',
    warning: 'bg-amber-50 border-amber-200 text-amber-700 dark:bg-amber-900/20 dark:border-amber-900/50 dark:text-amber-400',
    bad: 'bg-red-50 border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-900/50 dark:text-red-400',
    neutral: 'bg-slate-50 border-slate-200 text-slate-700 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300',
  }
  return (
    <div className={`p-3 rounded-lg border ${colors[status]}`}>
      <div className="flex items-center gap-1 mb-1">
        <p className="text-xs opacity-75">{label}</p>
        {help && <HelpTip content={help} className="!text-current opacity-75 hover:opacity-100" />}
      </div>
      <p className="text-lg font-semibold">{value}</p>
    </div>
  )
}

function FeatureCheck({ label, configured, detected }: { label: string; configured?: boolean; detected?: boolean }) {
  const { t } = useTranslation('proxyHost')
  const match = configured === detected
  const icon = detected ? (
    <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  ) : (
    <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
  )

  return (
    <div className={`flex items-center justify-between p-2 rounded-lg ${match
      ? 'bg-slate-50 dark:bg-slate-800'
      : 'bg-amber-50 dark:bg-amber-900/20'}`}>
      <span className="text-sm text-slate-700 dark:text-slate-300">{label}</span>
      <div className="flex items-center gap-2">
        {icon}
        {!match && configured && !detected && (
          <span className="text-xs text-amber-600 dark:text-amber-400">{t('test.notDetected')}</span>
        )}
      </div>
    </div>
  )
}

// SSL Tab
function SSLTab({ result }: { result: ProxyHostTestResult }) {
  const { t } = useTranslation('proxyHost')
  const ssl = result.ssl

  if (!ssl?.enabled) {
    return (
      <div className="text-center py-8 text-slate-500">
        <svg className="w-12 h-12 mx-auto mb-3 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        <p className="dark:text-slate-400">{t('test.sslNotEnabled')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* SSL Status */}
      <div className={`p-4 rounded-lg ${ssl.valid
        ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800'
        : 'bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800'}`}>
        <div className="flex items-center gap-2">
          {ssl.valid ? (
            <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          ) : (
            <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          )}
          <span className={`font-medium ${ssl.valid ? 'text-green-700' : 'text-red-700'}`}>
            {ssl.valid ? t('test.validCert') : t('test.invalidCert')}
          </span>
        </div>
        {ssl.error && <p className="text-sm text-red-600 dark:text-red-400 mt-2">{ssl.error}</p>}
      </div>

      {/* Certificate Details */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
        <table className="w-full">
          <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
            <DetailRow label={t('test.sslDetails.protocol')} value={ssl.protocol} help={t('test.help.sslDetails.protocol')} />
            <DetailRow label={t('test.sslDetails.cipherSuite')} value={ssl.cipher} help={t('test.help.sslDetails.cipherSuite')} />
            <DetailRow label={t('test.sslDetails.subject')} value={ssl.subject} />
            <DetailRow label={t('test.sslDetails.issuer')} value={ssl.issuer} />
            <DetailRow label={t('test.sslDetails.validFrom')} value={ssl.not_before ? new Date(ssl.not_before).toLocaleDateString() : undefined} help={t('test.help.sslDetails.validity')} />
            <DetailRow label={t('test.sslDetails.validUntil')} value={ssl.not_after ? new Date(ssl.not_after).toLocaleDateString() : undefined} />
            <DetailRow
              label={t('test.sslDetails.daysRemaining')}
              value={ssl.days_remaining?.toString()}
              highlight={ssl.days_remaining !== undefined && ssl.days_remaining < 30 ? 'warning' : undefined}
              help={t('test.help.sslDetails.daysRemaining')}
            />
          </tbody>
        </table>
      </div>
    </div>
  )
}

// HTTP Tab
function HTTPTab({ result, host }: { result: ProxyHostTestResult; host: ProxyHost }) {
  const { t } = useTranslation('proxyHost')
  const http = result.http

  return (
    <div className="space-y-4">
      {/* Protocol Version */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">{t('test.http.protocolInfo')}</h4>
        <div className="grid grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
            <div className="flex items-center gap-1">
              <span className="text-sm text-slate-600 dark:text-slate-400">{t('test.http.detectedProtocol')}</span>
              <HelpTip content={t('test.help.protocol')} />
            </div>
            <span className="font-medium text-slate-900 dark:text-white">{http?.protocol || 'Unknown'}</span>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
            <div className="flex items-center gap-1">
              <span className="text-sm text-slate-600 dark:text-slate-400">{t('test.responseTime')}</span>
              <HelpTip content={t('test.help.responseTime')} />
            </div>
            <span className="font-medium text-slate-900 dark:text-white">{result.response_time_ms}ms</span>
          </div>
        </div>
      </div>

      {/* HTTP Version Support */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">{t('test.http.versionSupport')}</h4>
        <div className="space-y-3">
          {/* HTTP/2 */}
          <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-700/50">
            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${http?.http2_enabled ? 'bg-green-100 dark:bg-green-900/30' : 'bg-slate-200 dark:bg-slate-600'}`}>
                <span className="text-xs font-bold text-slate-600 dark:text-slate-300">H2</span>
              </div>
              <div>
                <div className="flex items-center gap-1">
                  <p className="font-medium text-slate-900 dark:text-white">HTTP/2</p>
                  <HelpTip content={t('test.help.http.http2')} />
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('test.http.multiplexing')}</p>
              </div>
            </div>
            <StatusBadge enabled={http?.http2_enabled} configured={host.ssl_http2} />
          </div>

          {/* HTTP/3 */}
          <div className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-700/50">
            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${http?.http3_enabled ? 'bg-emerald-100 dark:bg-emerald-900/30' : 'bg-slate-200 dark:bg-slate-600'}`}>
                <span className="text-xs font-bold text-slate-600 dark:text-slate-300">H3</span>
              </div>
              <div>
                <div className="flex items-center gap-1">
                  <p className="font-medium text-slate-900 dark:text-white">HTTP/3 (QUIC)</p>
                  <HelpTip content={t('test.help.http.http3')} />
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('test.http.quic')}</p>
              </div>
            </div>
            <StatusBadge enabled={http?.http3_enabled} configured={host.ssl_http3} />
          </div>
        </div>
      </div>

      {/* Alt-Svc Header */}
      {http?.alt_svc_header && (
        <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
          <div className="flex items-center gap-1 mb-2">
            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('test.http.altSvc')}</h4>
            <HelpTip content={t('test.help.http.altSvc')} />
          </div>
          <code className="block p-3 bg-slate-50 dark:bg-slate-900 rounded text-xs text-slate-700 dark:text-slate-300 break-all">
            {http.alt_svc_header}
          </code>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
            {t('test.http.altSvcDesc')}
          </p>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ enabled, configured }: { enabled?: boolean; configured?: boolean }) {
  const { t } = useTranslation('proxyHost')
  if (enabled) {
    return <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">{t('status.active')}</span>
  }
  if (configured && !enabled) {
    return <span className="px-2 py-1 text-xs font-medium rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">{t('test.notDetected')}</span>
  }
  return <span className="px-2 py-1 text-xs font-medium rounded-full bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400">{t('test.disabled')}</span>
}

// Cache Tab
function CacheTab({ result, host }: { result: ProxyHostTestResult; host: ProxyHost }) {
  const { t } = useTranslation('proxyHost')
  const cache = result.cache

  return (
    <div className="space-y-4">
      {/* Cache Status */}
      <div className={`p-4 rounded-lg ${cache?.cache_status
        ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800'
        : 'bg-slate-50 border border-slate-200 dark:bg-slate-800 dark:border-slate-700'}`}>
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${cache?.cache_status
            ? 'bg-green-100 dark:bg-green-900/30'
            : 'bg-slate-200 dark:bg-slate-700'}`}>
            <svg className={`w-5 h-5 ${cache?.cache_status
              ? 'text-green-600 dark:text-green-400'
              : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-1">
              <h3 className={`font-medium ${cache?.cache_status ? 'text-green-800 dark:text-green-300' : 'text-slate-700 dark:text-slate-300'}`}>
                {cache?.cache_status ? `${t('test.cache.status')} ${cache.cache_status}` : t('test.cache.noStatus')}
              </h3>
              <HelpTip content={t('test.help.cache.status')} />
            </div>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {host.cache_enabled ? t('test.cache.enabled') : t('test.cache.disabled')}
            </p>
          </div>
        </div>
      </div>

      {/* Cache Headers */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 flex items-center gap-1">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('test.cache.headers')}</h4>
          <HelpTip content={t('test.help.cache.control')} />
        </div>
        <table className="w-full">
          <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
            <DetailRow label="X-Cache-Status" value={cache?.cache_status} description="Nginx cache status" />
            <DetailRow label="Cache-Control" value={cache?.cache_control} description="Browser caching directives" />
            <DetailRow label="Expires" value={cache?.expires} description="Expiration date" />
            <DetailRow label="ETag" value={cache?.etag} description="Resource version identifier" />
            <DetailRow label="Last-Modified" value={cache?.last_modified} description="Resource modification date" />
          </tbody>
        </table>
      </div>

      {/* Cache Status Legend */}
      <div className="bg-slate-50 dark:bg-slate-800 rounded-lg p-4">
        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{t('test.cache.legend')}</h4>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div><span className="font-medium text-green-600 dark:text-green-400">HIT</span> - <span className="dark:text-slate-400">{t('test.cache.hit')}</span></div>
          <div><span className="font-medium text-amber-600 dark:text-amber-400">MISS</span> - <span className="dark:text-slate-400">{t('test.cache.miss')}</span></div>
          <div><span className="font-medium text-blue-600 dark:text-blue-400">EXPIRED</span> - <span className="dark:text-slate-400">{t('test.cache.expired')}</span></div>
          <div><span className="font-medium text-slate-600 dark:text-slate-500">BYPASS</span> - <span className="dark:text-slate-400">{t('test.cache.bypass')}</span></div>
        </div>
      </div>
    </div>
  )
}

// Security Tab
function SecurityTab({ result }: { result: ProxyHostTestResult }) {
  const { t } = useTranslation('proxyHost')
  const sec = result.security

  const headers = [
    { name: 'HSTS', value: sec?.hsts_value, enabled: sec?.hsts, description: t('test.security.desc.hsts') },
    { name: 'X-Frame-Options', value: sec?.x_frame_options, enabled: !!sec?.x_frame_options, description: t('test.security.desc.xframe') },
    { name: 'X-Content-Type-Options', value: sec?.x_content_type_options, enabled: !!sec?.x_content_type_options, description: t('test.security.desc.xcontent') },
    { name: 'X-XSS-Protection', value: sec?.xss_protection, enabled: !!sec?.xss_protection, description: t('test.security.desc.xxss') },
    { name: 'Referrer-Policy', value: sec?.referrer_policy, enabled: !!sec?.referrer_policy, description: t('test.security.desc.referrer') },
    { name: 'Permissions-Policy', value: sec?.permissions_policy, enabled: !!sec?.permissions_policy, description: t('test.security.desc.permissions') },
    { name: 'Content-Security-Policy', value: sec?.content_security_policy, enabled: !!sec?.content_security_policy, description: t('test.security.desc.csp') },
  ]

  const enabledCount = headers.filter(h => h.enabled).length

  return (
    <div className="space-y-4">
      {/* Security Score */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-1">
            <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('test.security.score')}</h4>
            <HelpTip content={t('test.help.security.score')} />
          </div>
          <span className={`text-2xl font-bold ${enabledCount >= 5 ? 'text-green-600 dark:text-green-400' : enabledCount >= 3 ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400'}`}>
            {enabledCount}/{headers.length}
          </span>
        </div>
        <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2">
          <div
            className={`h-2 rounded-full ${enabledCount >= 5 ? 'bg-green-500' : enabledCount >= 3 ? 'bg-amber-500' : 'bg-red-500'}`}
            style={{ width: `${(enabledCount / headers.length) * 100}%` }}
          />
        </div>
      </div>

      {/* Server Header Warning */}
      {sec?.server_header && (
        <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-900/50 rounded-lg flex items-start gap-2">
          <svg className="w-5 h-5 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div>
            <div className="flex items-center gap-1">
              <p className="text-sm font-medium text-amber-800 dark:text-amber-300">{t('test.security.serverExposed')}</p>
              <HelpTip content={t('test.help.security.server')} />
            </div>
            <p className="text-xs text-amber-600 dark:text-amber-400">Server: {sec.server_header}</p>
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">{t('test.security.hideServer')}</p>
          </div>
        </div>
      )}

      {/* Headers List */}
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('test.security.headers')}</h4>
        </div>
        <div className="divide-y divide-slate-100">
          {headers.map(header => (
            <div key={header.name} className="px-4 py-3">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  {header.enabled ? (
                    <svg className="w-4 h-4 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <svg className="w-4 h-4 text-slate-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  )}
                  <div className="flex items-center gap-1">
                    <span className={`font-medium ${header.enabled ? 'text-slate-900 dark:text-white' : 'text-slate-400 dark:text-slate-500'}`}>
                      {header.name}
                    </span>
                    {header.description && <HelpTip content={header.description} />}
                  </div>
                </div>
                <span className="text-xs text-slate-500 dark:text-slate-400">{header.description}</span>
              </div>
              {header.value && (
                <code className="block mt-1 p-2 bg-slate-50 dark:bg-slate-900 rounded text-xs text-slate-600 dark:text-slate-400 break-all">
                  {header.value}
                </code>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// Headers Tab
function HeadersTab({ result }: { result: ProxyHostTestResult }) {
  const { t } = useTranslation('proxyHost')
  const headers = result.headers || {}
  const entries = Object.entries(headers).sort((a, b) => a[0].localeCompare(b[0]))

  return (
    <div className="space-y-4">
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('test.headers.response')}</h4>
          <span className="text-xs text-slate-500 dark:text-slate-400">{entries.length} {t('test.headers.count')}</span>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-700 max-h-96 overflow-auto">
          {entries.length === 0 ? (
            <div className="p-4 text-center text-slate-500 dark:text-slate-400 text-sm">{t('test.headers.none')}</div>
          ) : (
            entries.map(([key, value]) => (
              <div key={key} className="px-4 py-2 hover:bg-slate-50 dark:hover:bg-slate-700/50">
                <div className="flex items-start gap-4">
                  <span className="text-sm font-mono font-medium text-slate-700 dark:text-slate-300 min-w-[200px]">{key}</span>
                  <span className="text-sm font-mono text-slate-500 dark:text-slate-400 break-all">{value}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function DetailRow({ label, value, description, highlight, help }: { label: string; value?: string; description?: string; highlight?: 'warning', help?: string }) {
  return (
    <tr>
      <td className="px-4 py-2 text-sm text-slate-500 dark:text-slate-400 w-1/3">
        <div className="flex items-center gap-1">
          {label}
          {help && <HelpTip content={help} />}
        </div>
      </td>
      <td className={`px-4 py-2 text-sm font-mono ${highlight === 'warning' ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'}`}>
        {value || <span className="text-slate-300 dark:text-slate-600">-</span>}
        {description && <span className="block text-xs text-slate-400 dark:text-slate-500 font-sans mt-0.5">{description}</span>}
      </td>
    </tr>
  )
}

type SortBy = 'name' | 'updated' | 'created'
type SortOrder = 'asc' | 'desc'

const PER_PAGE_OPTIONS = [10, 20, 50] as const

export function ProxyHostList({ onEdit, onAdd }: ProxyHostListProps) {
  const { t } = useTranslation('proxyHost')
  const queryClient = useQueryClient()
  const [healthStatus, setHealthStatus] = useState<HealthStatus>({})
  const [testingHost, setTestingHost] = useState<ProxyHost | null>(null)
  const [testResult, setTestResult] = useState<ProxyHostTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [isTestLoading, setIsTestLoading] = useState(false)
  const [toggleConfirmHost, setToggleConfirmHost] = useState<ProxyHost | null>(null)
  const [searchInput, setSearchInput] = useState('')  // For controlled input
  const [searchQuery, setSearchQuery] = useState('')  // For actual query (debounced)
  const [currentPage, setCurrentPage] = useState(1)

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== searchQuery) {
        setSearchQuery(searchInput)
        setCurrentPage(1)
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [searchInput, searchQuery])
  const [perPage, setPerPage] = useState<number>(() => {
    const saved = localStorage.getItem('proxyHostPerPage')
    return saved ? parseInt(saved, 10) : 20
  })
  const [sortBy, setSortBy] = useState<SortBy>(() => {
    const saved = localStorage.getItem('proxyHostSortBy')
    return (saved as SortBy) || 'name'
  })
  const [sortOrder, setSortOrder] = useState<SortOrder>(() => {
    const saved = localStorage.getItem('proxyHostSortOrder')
    return (saved as SortOrder) || 'asc'
  })

  const { data, isLoading, error } = useQuery({
    queryKey: ['proxy-hosts', currentPage, perPage, searchQuery, sortBy, sortOrder],
    queryFn: () => fetchProxyHosts(currentPage, perPage, searchQuery, sortBy, sortOrder),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteProxyHost,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateProxyHost(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
    },
  })

  const handleToggle = (host: ProxyHost) => {
    setToggleConfirmHost(host)
  }

  const confirmToggle = () => {
    if (toggleConfirmHost) {
      toggleMutation.mutate({ id: toggleConfirmHost.id, enabled: !toggleConfirmHost.enabled })
      setToggleConfirmHost(null)
    }
  }

  // Check health status for all hosts on load
  useEffect(() => {
    const hosts = data?.data || []
    hosts.forEach((host) => {
      if (!healthStatus[host.id]) {
        checkHealth(host.id)
      }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.data])

  const checkHealth = async (hostId: string) => {
    setHealthStatus((prev) => ({ ...prev, [hostId]: 'checking' }))
    try {
      const result = await testProxyHost(hostId)
      setHealthStatus((prev) => ({
        ...prev,
        [hostId]: result.status === 'ok' ? 'online' : 'offline',
      }))
    } catch {
      setHealthStatus((prev) => ({ ...prev, [hostId]: 'offline' }))
    }
  }

  const handleDelete = async (id: string) => {
    if (confirm(t('actions.deleteConfirm'))) {
      deleteMutation.mutate(id)
    }
  }

  const handleTestConfig = async (host: ProxyHost) => {
    setTestingHost(host)
    setTestResult(null)
    setTestError(null)
    setIsTestLoading(true)

    try {
      const result = await testProxyHostConfig(host.id)
      setTestResult(result)
    } catch (err) {
      setTestError((err as Error).message)
    } finally {
      setIsTestLoading(false)
    }
  }

  const handleRetest = async () => {
    if (!testingHost) return
    handleTestConfig(testingHost)
  }

  const getDomainUrl = (domain: string, sslEnabled: boolean) => {
    return `${sslEnabled ? 'https' : 'http'}://${domain}`
  }

  // Hosts are now sorted server-side
  const hosts = data?.data || []

  // Handle search input change (debounced via useEffect)
  const handleSearchChange = (value: string) => {
    setSearchInput(value)
  }

  // Clear search
  const handleClearSearch = () => {
    setSearchInput('')
    setSearchQuery('')
    setCurrentPage(1)
  }

  // Handle per page change
  const handlePerPageChange = (value: number) => {
    setPerPage(value)
    setCurrentPage(1)
    localStorage.setItem('proxyHostPerPage', value.toString())
  }

  // Pagination helpers
  const totalPages = data?.total_pages || 1
  const total = data?.total || 0

  const getHealthDot = (hostId: string) => {
    const status = healthStatus[hostId]
    if (status === 'checking') {
      return <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" title="Checking..." />
    }
    if (status === 'online') {
      return <span className="w-2 h-2 rounded-full bg-green-500" title="Online" />
    }
    if (status === 'offline') {
      return <span className="w-2 h-2 rounded-full bg-red-500" title="Offline" />
    }
    return <span className="w-2 h-2 rounded-full bg-slate-300" title="Unknown" />
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
        Error loading proxy hosts: {(error as Error).message}
      </div>
    )
  }

  return (
    <div>
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('list.title')}</h2>

        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          {/* Search */}
          <div className="relative flex-1 sm:flex-none">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={searchInput}
              onChange={(e) => handleSearchChange(e.target.value)}
              placeholder={t('list.search')}
              className="w-full sm:w-48 pl-9 pr-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
            />
            {searchInput && (
              <button
                onClick={handleClearSearch}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600"
              >
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>

          {/* Sort */}
          <select
            value={`${sortBy}-${sortOrder}`}
            onChange={(e) => {
              const [by, order] = e.target.value.split('-') as [SortBy, SortOrder]
              setSortBy(by)
              setSortOrder(order)
              setCurrentPage(1)
              localStorage.setItem('proxyHostSortBy', by)
              localStorage.setItem('proxyHostSortOrder', order)
            }}
            className="px-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          >
            <option value="name-asc">{t('list.sort.nameAsc')}</option>
            <option value="name-desc">{t('list.sort.nameDesc')}</option>
            <option value="updated-desc">{t('list.sort.updatedDesc')}</option>
            <option value="updated-asc">{t('list.sort.updatedAsc')}</option>
            <option value="created-desc">{t('list.sort.createdDesc')}</option>
            <option value="created-asc">{t('list.sort.createdAsc')}</option>
          </select>

          <button
            onClick={onAdd}
            className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            {t('list.addNew')}
          </button>
        </div>
      </div>

      {hosts.length === 0 ? (
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-8 text-center border border-dashed border-slate-200 dark:border-slate-700">
          <div className="w-12 h-12 bg-slate-200 dark:bg-slate-700 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {searchInput ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              )}
            </svg>
          </div>
          <h3 className="text-slate-600 dark:text-slate-300 font-medium mb-1">
            {searchInput ? t('list.noResults') : t('list.empty')}
          </h3>
          <p className="text-slate-400 text-sm">
            {searchInput ? t('list.noResultsDescription', { query: searchInput }) : t('list.emptyDescription')}
          </p>
          {searchInput && (
            <button
              onClick={handleClearSearch}
              className="mt-3 text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              {t('list.clearSearch')}
            </button>
          )}
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
          <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('list.columns.source')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('list.columns.destination')}
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('list.columns.features')}
                </th>
                <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('list.columns.status')}
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('list.columns.actions')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              {hosts.map((host) => (
                <tr key={host.id} className={`hover:bg-slate-50 dark:hover:bg-slate-700/50 ${!host.enabled ? 'opacity-50' : ''}`}>
                  {/* Source (Domains) */}
                  <td className="px-4 py-3">
                    <div className="flex flex-col gap-1">
                      {host.domain_names.map((domain, idx) => (
                        <a
                          key={idx}
                          href={getDomainUrl(domain, host.ssl_enabled)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-sm text-slate-700 dark:text-slate-300 hover:text-primary-600 dark:hover:text-primary-400 group"
                        >
                          {host.ssl_enabled && (
                            <svg className="w-3 h-3 text-green-600 dark:text-green-500" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                            </svg>
                          )}
                          <span className="font-medium">{domain}</span>
                          <svg className="w-3 h-3 text-slate-400 group-hover:text-primary-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                          </svg>
                        </a>
                      ))}
                    </div>
                  </td>

                  {/* Destination (Forward To) */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {getHealthDot(host.id)}
                      <code className="text-sm text-slate-600 dark:text-slate-400">
                        {host.forward_scheme}://{host.forward_host}:{host.forward_port}
                      </code>
                      <button
                        onClick={() => checkHealth(host.id)}
                        className="p-0.5 text-slate-400 hover:text-blue-600 dark:hover:text-blue-400"
                        title="Refresh status"
                      >
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                      </button>
                    </div>
                  </td>

                  {/* Features */}
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap justify-center gap-1">
                      {host.ssl_enabled && (
                        <button
                          onClick={() => onEdit(host, 'ssl')}
                          className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-100 text-green-700 hover:bg-green-200 transition-colors cursor-pointer"
                          title="Click to edit SSL settings"
                        >
                          SSL{host.ssl_http2 ? '+H2' : ''}{host.ssl_http3 ? '+H3' : ''}
                        </button>
                      )}
                      {host.ssl_http3 && (
                        <button
                          onClick={() => onEdit(host, 'ssl')}
                          className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-emerald-100 text-emerald-700 hover:bg-emerald-200 transition-colors cursor-pointer"
                          title="Click to edit HTTP/3 settings"
                        >
                          QUIC
                        </button>
                      )}
                      {host.waf_enabled && (
                        <button
                          onClick={() => onEdit(host, 'security')}
                          className={`px-1.5 py-0.5 text-[10px] font-medium rounded hover:opacity-80 transition-opacity cursor-pointer ${host.waf_mode === 'blocking' ? 'bg-purple-100 text-purple-700 hover:bg-purple-200' : 'bg-amber-100 text-amber-700 hover:bg-amber-200'
                            }`}
                          title={`Click to edit WAF settings (${host.waf_mode})`}
                        >
                          WAF
                        </button>
                      )}
                      {host.allow_websocket_upgrade && (
                        <button
                          onClick={() => onEdit(host, 'performance')}
                          className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-cyan-100 text-cyan-700 hover:bg-cyan-200 transition-colors cursor-pointer"
                          title="Click to edit WebSocket settings"
                        >
                          WS
                        </button>
                      )}
                      {host.cache_enabled && (
                        <button
                          onClick={() => onEdit(host, 'performance')}
                          className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-indigo-100 text-indigo-700 hover:bg-indigo-200 transition-colors cursor-pointer"
                          title="Click to edit Cache settings"
                        >
                          Cache
                        </button>
                      )}
                      {host.block_exploits && (
                        <button
                          onClick={() => onEdit(host, 'security')}
                          className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-red-100 text-red-700 hover:bg-red-200 transition-colors cursor-pointer"
                          title="Click to edit Exploit Block settings"
                        >
                          Exploits
                        </button>
                      )}
                    </div>
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => handleToggle(host)}
                      disabled={toggleMutation.isPending}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${host.enabled
                        ? 'bg-green-100 text-green-800 hover:bg-green-200'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                        }`}
                      title={host.enabled ? 'Click to disable' : 'Click to enable'}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${host.enabled ? 'bg-green-500' : 'bg-slate-400'}`} />
                      {host.enabled ? t('list.status.active') : t('list.status.disabled')}
                    </button>
                  </td>

                  {/* Actions */}
                  <td className="px-4 py-3 text-right">
                    <div className="flex justify-end gap-1">
                      <button
                        onClick={() => handleTestConfig(host)}
                        className="p-1.5 text-slate-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 dark:hover:text-blue-400 rounded transition-colors"
                        title={t('actions.testConfig')}
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </button>
                      <button
                        onClick={() => onEdit(host)}
                        className="p-1.5 text-slate-400 hover:text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-900/30 dark:hover:text-primary-400 rounded transition-colors"
                        title={t('actions.edit')}
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>

                      <button
                        onClick={() => handleDelete(host.id)}
                        className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30 dark:hover:text-red-400 rounded transition-colors"
                        title={t('actions.delete')}
                      >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
      }

      {/* Pagination */}
      {total > 0 && (
        <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="text-sm text-slate-500 dark:text-slate-400">
              {t('list.showing', {
                from: (currentPage - 1) * perPage + 1,
                to: Math.min(currentPage * perPage, total),
                total
              })}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-slate-500 dark:text-slate-400">{t('list.perPage')}:</span>
              <select
                value={perPage}
                onChange={(e) => handlePerPageChange(Number(e.target.value))}
                className="px-2 py-1 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                {PER_PAGE_OPTIONS.map(option => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {/* First Page */}
            <button
              onClick={() => setCurrentPage(1)}
              disabled={currentPage === 1}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.first')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
              </svg>
            </button>
            {/* Previous Page */}
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.previous')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </button>

            {/* Page Numbers */}
            <div className="flex items-center gap-1 px-2">
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum: number
                if (totalPages <= 5) {
                  pageNum = i + 1
                } else if (currentPage <= 3) {
                  pageNum = i + 1
                } else if (currentPage >= totalPages - 2) {
                  pageNum = totalPages - 4 + i
                } else {
                  pageNum = currentPage - 2 + i
                }
                return (
                  <button
                    key={pageNum}
                    onClick={() => setCurrentPage(pageNum)}
                    className={`min-w-[32px] h-8 px-2 text-sm font-medium rounded-lg transition-colors ${
                      currentPage === pageNum
                        ? 'bg-primary-600 text-white'
                        : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700'
                    }`}
                  >
                    {pageNum}
                  </button>
                )
              })}
            </div>

            {/* Next Page */}
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.next')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
            {/* Last Page */}
            <button
              onClick={() => setCurrentPage(totalPages)}
              disabled={currentPage === totalPages}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.last')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" />
              </svg>
            </button>
          </div>
        </div>
      )}

      {/* Test Result Modal */}
      {
        testingHost && (
          <TestResultModal
            host={testingHost}
            result={testResult}
            isLoading={isTestLoading}
            error={testError}
            onClose={() => {
              setTestingHost(null)
              setTestResult(null)
              setTestError(null)
            }}
            onRetest={handleRetest}
          />
        )
      }

      {/* Toggle Confirmation Modal */}
      {
        toggleConfirmHost && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl shadow-xl w-full max-w-md overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-200">
                <h3 className="text-lg font-semibold text-slate-900">
                  {toggleConfirmHost.enabled ? t('actions.disableConfirmTitle') : t('actions.enableConfirmTitle')}
                </h3>
              </div>
              <div className="px-6 py-4">
                <p className="text-slate-600">
                  {toggleConfirmHost.enabled
                    ? t('actions.disableConfirmMessage', { domain: toggleConfirmHost.domain_names[0] })
                    : t('actions.enableConfirmMessage', { domain: toggleConfirmHost.domain_names[0] })}
                </p>
              </div>
              <div className="px-6 py-4 bg-slate-50 flex justify-end gap-3">
                <button
                  onClick={() => setToggleConfirmHost(null)}
                  className="px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 rounded-lg transition-colors"
                >
                  {t('common:buttons.cancel')}
                </button>
                <button
                  onClick={confirmToggle}
                  disabled={toggleMutation.isPending}
                  className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors ${toggleConfirmHost.enabled
                    ? 'bg-red-600 hover:bg-red-700'
                    : 'bg-green-600 hover:bg-green-700'
                    } disabled:opacity-50`}
                >
                  {toggleMutation.isPending
                    ? t('common:status.processing')
                    : toggleConfirmHost.enabled
                      ? t('actions.disable')
                      : t('actions.enable')}
                </button>
              </div>
            </div>
          </div>
        )
      }
    </div >
  )
}

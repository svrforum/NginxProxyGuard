import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import type { ProxyHost, ProxyHostTestResult } from '../../types/proxy-host';

// Summary Tab
export function SummaryTab({ result, host }: { result: ProxyHostTestResult; host: ProxyHost }) {
  const { t } = useTranslation('proxyHost');
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
  );
}

export function StatCard({ label, value, status, help }: { label: string; value: string; status: 'good' | 'warning' | 'bad' | 'neutral', help?: string }) {
  const colors = {
    good: 'bg-green-50 border-green-200 text-green-700 dark:bg-green-900/20 dark:border-green-900/50 dark:text-green-400',
    warning: 'bg-amber-50 border-amber-200 text-amber-700 dark:bg-amber-900/20 dark:border-amber-900/50 dark:text-amber-400',
    bad: 'bg-red-50 border-red-200 text-red-700 dark:bg-red-900/20 dark:border-red-900/50 dark:text-red-400',
    neutral: 'bg-slate-50 border-slate-200 text-slate-700 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300',
  };
  return (
    <div className={`p-3 rounded-lg border ${colors[status]}`}>
      <div className="flex items-center gap-1 mb-1">
        <p className="text-xs opacity-75">{label}</p>
        {help && <HelpTip content={help} className="!text-current opacity-75 hover:opacity-100" />}
      </div>
      <p className="text-lg font-semibold">{value}</p>
    </div>
  );
}

export function FeatureCheck({ label, configured, detected }: { label: string; configured?: boolean; detected?: boolean }) {
  const { t } = useTranslation('proxyHost');
  const match = configured === detected;
  const icon = detected ? (
    <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  ) : (
    <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
  );

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
  );
}

// Shared helper used by SSL/Cache tabs
export function DetailRow({ label, value, description, highlight, help }: { label: string; value?: string; description?: string; highlight?: 'warning', help?: string }) {
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
  );
}

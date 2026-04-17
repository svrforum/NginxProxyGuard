import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import type { ProxyHost, ProxyHostTestResult } from '../../types/proxy-host';
import { DetailRow } from './TestResultSummary';

// SSL Tab
export function SSLTab({ result }: { result: ProxyHostTestResult }) {
  const { t } = useTranslation('proxyHost');
  const ssl = result.ssl;

  if (!ssl?.enabled) {
    return (
      <div className="text-center py-8 text-slate-500">
        <svg className="w-12 h-12 mx-auto mb-3 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        <p className="dark:text-slate-400">{t('test.sslNotEnabled')}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
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
          <span className={`font-medium ${ssl.valid ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'}`}>
            {ssl.valid ? t('test.validCert') : t('test.invalidCert')}
          </span>
        </div>
        {ssl.error && <p className="text-sm text-red-600 dark:text-red-400 mt-2">{ssl.error}</p>}
      </div>

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
  );
}

// HTTP Tab
export function HTTPTab({ result, host }: { result: ProxyHostTestResult; host: ProxyHost }) {
  const { t } = useTranslation('proxyHost');
  const http = result.http;

  return (
    <div className="space-y-4">
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

      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-4">
        <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">{t('test.http.versionSupport')}</h4>
        <div className="space-y-3">
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
  );
}

function StatusBadge({ enabled, configured }: { enabled?: boolean; configured?: boolean }) {
  const { t } = useTranslation('proxyHost');
  if (enabled) {
    return <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">{t('status.active')}</span>;
  }
  if (configured && !enabled) {
    return <span className="px-2 py-1 text-xs font-medium rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">{t('test.notDetected')}</span>;
  }
  return <span className="px-2 py-1 text-xs font-medium rounded-full bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400">{t('test.disabled')}</span>;
}

// Cache Tab
export function CacheTab({ result, host }: { result: ProxyHostTestResult; host: ProxyHost }) {
  const { t } = useTranslation('proxyHost');
  const cache = result.cache;

  return (
    <div className="space-y-4">
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
  );
}

import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import type { ProxyHostTestResult } from '../../types/proxy-host';

// Security Tab
export function SecurityTab({ result }: { result: ProxyHostTestResult }) {
  const { t } = useTranslation('proxyHost');
  const sec = result.security;

  const headers = [
    { name: 'HSTS', value: sec?.hsts_value, enabled: sec?.hsts, description: t('test.security.desc.hsts') },
    { name: 'X-Frame-Options', value: sec?.x_frame_options, enabled: !!sec?.x_frame_options, description: t('test.security.desc.xframe') },
    { name: 'X-Content-Type-Options', value: sec?.x_content_type_options, enabled: !!sec?.x_content_type_options, description: t('test.security.desc.xcontent') },
    { name: 'X-XSS-Protection', value: sec?.xss_protection, enabled: !!sec?.xss_protection, description: t('test.security.desc.xxss') },
    { name: 'Referrer-Policy', value: sec?.referrer_policy, enabled: !!sec?.referrer_policy, description: t('test.security.desc.referrer') },
    { name: 'Permissions-Policy', value: sec?.permissions_policy, enabled: !!sec?.permissions_policy, description: t('test.security.desc.permissions') },
    { name: 'Content-Security-Policy', value: sec?.content_security_policy, enabled: !!sec?.content_security_policy, description: t('test.security.desc.csp') },
  ];

  const enabledCount = headers.filter(h => h.enabled).length;

  return (
    <div className="space-y-4">
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

      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
          <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('test.security.headers')}</h4>
        </div>
        <div className="divide-y divide-slate-100 dark:divide-slate-700">
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
  );
}

// Headers Tab
export function HeadersTab({ result }: { result: ProxyHostTestResult }) {
  const { t } = useTranslation('proxyHost');
  const headers = result.headers || {};
  const entries = Object.entries(headers).sort((a, b) => a[0].localeCompare(b[0]));

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
  );
}

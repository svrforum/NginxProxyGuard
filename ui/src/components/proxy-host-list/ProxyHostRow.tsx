import { memo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ProxyHost } from '../../types/proxy-host';
import type { TabType } from '../proxy-host/types';
import { IconButton, PencilIcon, TrashIcon } from '../common/listui';

// ProxyHostRow.tsx - houses the per-row toggle confirmation dialog and the
// memoized table row body. Splitting the row out lets `React.memo` skip
// re-renders on hosts whose props didn't change — searches and toggles on
// 200+ host lists noticeably stutter without it.

type HealthDot = 'checking' | 'online' | 'offline' | 'unknown';

interface ProxyHostRowProps {
  host: ProxyHost;
  healthStatus: HealthDot;
  togglePending: boolean;
  onEdit: (host: ProxyHost, tab?: TabType) => void;
  onDelete: (id: string) => void;
  onToggle: (host: ProxyHost) => void;
  onClone: (host: ProxyHost) => void;
  onTestConfig: (host: ProxyHost) => void;
  onCheckHealth: (hostId: string) => void;
  onFavorite: (hostId: string) => void;
}

function getDomainUrl(domain: string, sslEnabled: boolean) {
  return `${sslEnabled ? 'https' : 'http'}://${domain}`;
}

// Cap the per-row domain list so a multi-domain host (wildcard/SAN cert can
// front a dozen+ subdomains) doesn't tower the row and break the table's
// vertical rhythm. Mirrors the +N more / collapse toggle used on cert cards.
const MAX_VISIBLE_DOMAINS = 3;

function isStreamHost(host: ProxyHost) {
  return host.proxy_type === 'stream';
}

function streamSource(host: ProxyHost) {
  const protocol = (host.stream_protocol || 'tcp').toUpperCase();
  const listenHost = host.stream_listen_host?.trim() || '*';
  const listenPort = host.stream_listen_port || '?';
  return `${protocol} ${listenHost}:${listenPort}`;
}

function streamTarget(host: ProxyHost) {
  const protocol = host.stream_protocol || 'tcp';
  return `${protocol}://${host.forward_host}:${host.forward_port}`;
}

function renderHealthDot(status: HealthDot, t: (key: string) => string) {
  if (status === 'checking') {
    return <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" title={t('list.health.checking')} />;
  }
  if (status === 'online') {
    return <span className="w-2 h-2 rounded-full bg-green-500" title={t('list.health.online')} />;
  }
  if (status === 'offline') {
    return <span className="w-2 h-2 rounded-full bg-red-500" title={t('list.health.offline')} />;
  }
  return <span className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600" title={t('list.health.unknown')} />;
}

function ProxyHostRowImpl({
  host,
  healthStatus,
  togglePending,
  onEdit,
  onDelete,
  onToggle,
  onClone,
  onTestConfig,
  onCheckHealth,
  onFavorite,
}: ProxyHostRowProps) {
  const { t } = useTranslation('proxyHost');
  const isStream = isStreamHost(host);
  const [domainsExpanded, setDomainsExpanded] = useState(false);

  const visibleDomains = domainsExpanded
    ? host.domain_names
    : host.domain_names.slice(0, MAX_VISIBLE_DOMAINS);
  const hiddenDomainCount = host.domain_names.length - visibleDomains.length;
  const domainToggle = (host.domain_names.length > MAX_VISIBLE_DOMAINS) && (
    <button
      type="button"
      onClick={() => setDomainsExpanded((v) => !v)}
      className="self-start text-[11px] font-medium text-primary-600 dark:text-primary-400 hover:underline"
    >
      {domainsExpanded ? t('list.domainsCollapse') : t('list.domainsMore', { count: hiddenDomainCount })}
    </button>
  );

  return (
    <tr className={`hover:bg-slate-50 dark:hover:bg-slate-700/50 ${!host.enabled ? 'opacity-50' : ''}`}>
      {/* Source (Domains) */}
      <td className="px-4 py-3">
        <div className="flex items-start gap-1.5">
          <button
            onClick={() => onFavorite(host.id)}
            className={`mt-0.5 p-0.5 rounded transition-colors flex-shrink-0 ${
              host.is_favorite
                ? 'text-amber-400 hover:text-amber-500 dark:text-amber-400 dark:hover:text-amber-300'
                : 'text-slate-300 hover:text-amber-400 dark:text-slate-600 dark:hover:text-amber-400'
            }`}
            title={host.is_favorite ? t('actions.unfavorite') : t('actions.favorite')}
          >
            <svg className="w-4 h-4" fill={host.is_favorite ? 'currentColor' : 'none'} stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
            </svg>
          </button>
          {isStream ? (
            <div className="flex flex-col gap-1">
              <code className="text-sm font-medium text-slate-700 dark:text-slate-300">
                {streamSource(host)}
              </code>
              <div className="flex flex-wrap gap-1">
                {visibleDomains.map((domain, idx) => (
                  <span key={idx} className="inline-flex rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-600 dark:bg-slate-700 dark:text-slate-300">
                    {domain}
                  </span>
                ))}
              </div>
              {domainToggle}
            </div>
          ) : (
            <div className="flex flex-col gap-1">
              {visibleDomains.map((domain, idx) => (
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
              {domainToggle}
            </div>
          )}
        </div>
      </td>

      {/* Destination */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          {renderHealthDot(healthStatus, t)}
          <code className="text-sm text-slate-600 dark:text-slate-400">
            {isStream ? streamTarget(host) : `${host.forward_scheme}://${host.forward_host}:${host.forward_port}`}
          </code>
          <button
            onClick={() => onCheckHealth(host.id)}
            className="p-0.5 text-slate-400 hover:text-blue-600 dark:hover:text-blue-400"
            title={t('list.refreshStatus')}
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
          {isStream && (
            <button
              onClick={() => onEdit(host, 'basic')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-400 hover:bg-violet-200 dark:hover:bg-violet-900/50 transition-colors cursor-pointer"
              title={t('list.editStreamSettings')}
            >
              STREAM
            </button>
          )}
          {isStream && (
            <button
              onClick={() => onEdit(host, 'basic')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors cursor-pointer"
              title={t('list.editStreamProtocol')}
            >
              {(host.stream_protocol || 'tcp').toUpperCase()}
            </button>
          )}
          {isStream && host.stream_ssl_preread && (
            <button
              onClick={() => onEdit(host, 'basic')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-200 dark:hover:bg-emerald-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              SNI
            </button>
          )}
          {isStream && (host.stream_accept_proxy_protocol || host.stream_send_proxy_protocol) && (
            <button
              onClick={() => onEdit(host, 'basic')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-400 hover:bg-cyan-200 dark:hover:bg-cyan-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              PROXY
            </button>
          )}
          {!isStream && host.ssl_enabled && (
            <button
              onClick={() => onEdit(host, 'ssl')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              SSL{host.ssl_http2 ? '+H2' : ''}{host.ssl_http3 ? '+H3' : ''}
            </button>
          )}
          {!isStream && host.ssl_http3 && (
            <button
              onClick={() => onEdit(host, 'ssl')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-200 dark:hover:bg-emerald-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              QUIC
            </button>
          )}
          {!isStream && host.waf_enabled && (
            <button
              onClick={() => onEdit(host, 'security')}
              className={`px-1.5 py-0.5 text-[10px] font-medium rounded hover:opacity-80 transition-opacity cursor-pointer ${host.waf_mode === 'blocking' ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 hover:bg-purple-200 dark:hover:bg-purple-900/50' : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 hover:bg-amber-200 dark:hover:bg-amber-900/50'
                  }`}
              title={`Click to edit WAF settings (${host.waf_mode})`}
            >
              WAF
            </button>
          )}
          {!isStream && host.allow_websocket_upgrade && (
            <button
              onClick={() => onEdit(host, 'performance')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-400 hover:bg-cyan-200 dark:hover:bg-cyan-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              WS
            </button>
          )}
          {!isStream && host.cache_enabled && (
            <button
              onClick={() => onEdit(host, 'performance')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400 hover:bg-indigo-200 dark:hover:bg-indigo-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              Cache
            </button>
          )}
          {!isStream && host.block_exploits && (
            <button
              onClick={() => onEdit(host, 'security')}
              className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-900/50 transition-colors cursor-pointer"
              title={t('list.editFeatureHint')}
            >
              Exploits
            </button>
          )}
        </div>
      </td>

      {/* Status */}
      <td className="px-4 py-3 text-center">
        {host.config_status === 'error' ? (
          <button
            onClick={() => onEdit(host)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-900/50 transition-colors"
            title={host.config_error ? t('list.status.errorTooltip', { error: host.config_error }) : t('list.status.error')}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
            {t('list.status.error')}
          </button>
        ) : (
          <button
            onClick={() => onToggle(host)}
            disabled={togglePending}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${host.enabled
              ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-900/50'
              : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
              }`}
            title={host.enabled ? 'Click to disable' : 'Click to enable'}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${host.enabled ? 'bg-green-500' : 'bg-slate-400'}`} />
            {host.enabled ? t('list.status.active') : t('list.status.disabled')}
          </button>
        )}
      </td>

      {/* Actions */}
      <td className="px-4 py-3 text-right">
        <div className="flex items-center justify-end gap-0.5">
          <IconButton onClick={() => onTestConfig(host)} title={t('actions.testConfig')}>
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </IconButton>
          <IconButton onClick={() => onEdit(host)} title={t('actions.edit')}>
            <PencilIcon />
          </IconButton>
          <IconButton onClick={() => onClone(host)} title={t('actions.clone')}>
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
          </IconButton>
          <span className="ml-1 border-l border-slate-200 pl-1 dark:border-slate-600">
            <IconButton onClick={() => onDelete(host.id)} title={t('actions.delete')} variant="danger">
              <TrashIcon />
            </IconButton>
          </span>
        </div>
      </td>
    </tr>
  );
}

export const ProxyHostRow = memo(ProxyHostRowImpl);

interface ToggleConfirmDialogProps {
  host: ProxyHost;
  isPending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ToggleConfirmDialog({ host, isPending, onConfirm, onCancel }: ToggleConfirmDialogProps) {
  const { t } = useTranslation('proxyHost');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-md overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            {host.enabled ? t('actions.disableConfirmTitle') : t('actions.enableConfirmTitle')}
          </h3>
        </div>
        <div className="px-6 py-4">
          <p className="text-slate-600 dark:text-slate-400">
            {host.enabled
              ? t('actions.disableConfirmMessage', { domain: host.domain_names[0] })
              : t('actions.enableConfirmMessage', { domain: host.domain_names[0] })}
          </p>
        </div>
        <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            {t('common:buttons.cancel')}
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors ${
              host.enabled ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700'
            } disabled:opacity-50`}
          >
            {isPending
              ? t('common:status.processing')
              : host.enabled
                ? t('actions.disable')
                : t('actions.enable')}
          </button>
        </div>
      </div>
    </div>
  );
}

import { memo, type MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { Log } from '../../types/log';
import { formatBytes } from './utils';
import { StatusCodeBadge, BlockReasonBadge, MethodBadge, GeoIPBadge, BannedIPBadge } from './badges';
import type { AccessColumnKey } from './hooks/useColumnVisibility';

interface LogRowTypedProps {
  log: Log;
  logType?: 'access' | 'error' | 'modsec';
  onClick: () => void;
  // Fired when the user clicks the client IP cell. The handler is expected to apply
  // a "filter by this IP" — clicking the IP never opens the detail modal.
  onClientIPClick?: (ip: string) => void;
  // When omitted, every column renders. Only used for access logs.
  visibleColumns?: Set<AccessColumnKey>;
}

// Splits Nginx's comma-separated $upstream_addr / $upstream_status into trimmed parts.
// Empty and literal "-" entries (per-attempt placeholders for unreached upstreams) are kept
// so the retry count stays accurate.
function splitUpstream(value?: string): string[] {
  if (!value) return [];
  return value.split(',').map((part) => part.trim()).filter(Boolean);
}

export const LogRowTyped = memo(function LogRowTyped({ log, logType, onClick, onClientIPClick, visibleColumns }: LogRowTypedProps) {
  const { t, i18n } = useTranslation('logs');

  const formatTime = (time: string) => new Date(time).toLocaleString(i18n.language);

  const handleIPClick = (e: MouseEvent) => {
    if (!onClientIPClick || !log.client_ip) return;
    // Row has its own onClick that opens the detail modal; the IP click is a separate
    // affordance ("filter by this IP"), so swallow propagation.
    e.stopPropagation();
    onClientIPClick(log.client_ip);
  };

  if (logType === 'access') {
    const upstreamParts = splitUpstream(log.upstream_addr);
    const finalUpstream = upstreamParts[upstreamParts.length - 1];
    const retryCount = upstreamParts.length > 1 ? upstreamParts.length - 1 : 0;
    const upstreamTooltip = retryCount > 0
      ? `${t('table.upstreamRetryPath')}: ${upstreamParts.join(' → ')}`
      : finalUpstream;
    // `visibleColumns === undefined` means "show everything" — used by callers that
    // haven't opted into per-column control (e.g. the related-logs modal).
    const show = (key: AccessColumnKey) => !visibleColumns || visibleColumns.has(key);
    return (
      <tr className="hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors" onClick={onClick}>
        {show('time') && (
          <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
            {formatTime(log.timestamp)}
          </td>
        )}
        {show('host') && (
          <td className="px-4 py-3 text-sm text-primary-600 dark:text-primary-400 font-medium truncate" title={log.host}>
            {log.host || '-'}
          </td>
        )}
        {show('ip') && (
          <td className="px-4 py-3 overflow-hidden">
            {log.client_ip && onClientIPClick ? (
              <button
                type="button"
                onClick={handleIPClick}
                title={t('table.filterByIP', { ip: log.client_ip })}
                className="block w-full text-left hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded px-1 -mx-1 transition-colors"
              >
                <BannedIPBadge ip={log.client_ip} isBanned={log.is_banned} />
              </button>
            ) : (
              <BannedIPBadge ip={log.client_ip} isBanned={log.is_banned} />
            )}
          </td>
        )}
        {show('country') && (
          <td className="px-4 py-3 whitespace-nowrap">
            <GeoIPBadge log={log} />
          </td>
        )}
        {show('method') && (
          <td className="px-4 py-3 whitespace-nowrap">
            {log.request_method && <MethodBadge method={log.request_method} />}
          </td>
        )}
        {show('uri') && (
          <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-200 truncate font-mono" title={log.request_uri}>
            {log.request_uri || '-'}
          </td>
        )}
        {show('status') && (
          <td className="px-4 py-3">
            {log.status_code && <StatusCodeBadge code={log.status_code} />}
          </td>
        )}
        {show('block') && (
          <td className="px-4 py-3 whitespace-nowrap">
            <BlockReasonBadge reason={log.block_reason} category={log.bot_category} />
          </td>
        )}
        {show('size') && (
          <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
            {log.body_bytes_sent ? formatBytes(log.body_bytes_sent) : '-'}
          </td>
        )}
        {show('responseTime') && (
          <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
            {log.request_time ? `${log.request_time.toFixed(3)}s` : '-'}
          </td>
        )}
        {show('upstream') && (
          <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap" title={upstreamTooltip}>
            {finalUpstream ? (
              <span className="inline-flex items-center gap-1.5">
                <span className="font-mono truncate max-w-[120px]">{finalUpstream}</span>
                {retryCount > 0 && (
                  <span
                    className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400 text-[10px] font-medium"
                    aria-label={t('table.upstreamRetry', { count: retryCount })}
                  >
                    ↻{retryCount}
                  </span>
                )}
              </span>
            ) : (
              <span className="text-slate-400 dark:text-slate-500">{t('table.upstreamDirect')}</span>
            )}
          </td>
        )}
        {show('userAgent') && (
          <td className="px-4 py-3 overflow-hidden">
            <span
              className="block text-xs text-slate-500 dark:text-slate-400 truncate"
              title={log.http_user_agent || '-'}
            >
              {log.http_user_agent || '-'}
            </span>
          </td>
        )}
      </tr>
    );
  }

  if (logType === 'modsec') {
    return (
      <tr className="hover:bg-orange-50 dark:hover:bg-orange-900/10 cursor-pointer transition-colors" onClick={onClick}>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
          {formatTime(log.timestamp)}
        </td>
        <td className="px-4 py-3 text-sm text-orange-600 dark:text-orange-400 font-medium whitespace-nowrap">
          {log.host || '-'}
        </td>
        <td className="px-4 py-3 overflow-hidden">
          {log.client_ip && onClientIPClick ? (
            <button
              type="button"
              onClick={handleIPClick}
              title={t('table.filterByIP', { ip: log.client_ip })}
              className="block w-full text-left hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded px-1 -mx-1 transition-colors"
            >
              <BannedIPBadge ip={log.client_ip} isBanned={log.is_banned} />
            </button>
          ) : (
            <BannedIPBadge ip={log.client_ip} isBanned={log.is_banned} />
          )}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <GeoIPBadge log={log} />
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className="px-2 py-0.5 bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400 rounded text-xs font-mono">
            {log.rule_id || '-'}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-200 truncate max-w-[120px] sm:max-w-[180px] lg:max-w-[250px] xl:max-w-[350px]" title={log.rule_message}>
          {log.rule_message || '-'}
        </td>
        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 truncate font-mono max-w-[100px] sm:max-w-[150px] lg:max-w-[180px] xl:max-w-[250px]" title={log.request_uri}>
          {log.request_uri || '-'}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${log.action_taken === 'blocked'
            ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
            : log.action_taken === 'excluded'
              ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
              : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
            }`}>
            {log.action_taken === 'excluded' ? t('table.logType.pass') : log.action_taken || t('table.logType.logged')}
          </span>
        </td>
      </tr>
    );
  }

  if (logType === 'error') {
    const severityColors: Record<string, string> = {
      emerg: 'bg-red-600 text-white',
      alert: 'bg-red-500 text-white',
      crit: 'bg-red-400 text-white',
      error: 'bg-red-100 text-red-800',
      warn: 'bg-yellow-100 text-yellow-800',
      notice: 'bg-blue-100 text-blue-800',
      info: 'bg-slate-100 text-slate-800',
      debug: 'bg-slate-100 text-slate-600',
    };
    return (
      <tr className="hover:bg-red-50 dark:hover:bg-red-900/10 cursor-pointer transition-colors" onClick={onClick}>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
          {formatTime(log.timestamp)}
        </td>
        <td className="px-4 py-3">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityColors[log.severity || 'error'] || severityColors.error}`}>
            {log.severity || 'error'}
          </span>
        </td>
        <td className="px-4 py-3 overflow-hidden">
          {log.client_ip && onClientIPClick ? (
            <button
              type="button"
              onClick={handleIPClick}
              title={t('table.filterByIP', { ip: log.client_ip })}
              className="block w-full text-left hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded px-1 -mx-1 transition-colors"
            >
              <BannedIPBadge ip={log.client_ip} isBanned={log.is_banned} />
            </button>
          ) : (
            <BannedIPBadge ip={log.client_ip} isBanned={log.is_banned} />
          )}
        </td>
        <td className="px-4 py-3 text-sm text-red-700 dark:text-red-400 max-w-2xl truncate" title={log.error_message}>
          {log.error_message || '-'}
        </td>
      </tr>
    );
  }

  return null;
});

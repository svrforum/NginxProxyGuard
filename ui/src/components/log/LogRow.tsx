import { memo } from 'react';
import type { Log } from '../../types/log';
import { StatusCodeBadge, MethodBadge, GeoIPBadge, BlockReasonBadge } from './LogBadges';
import { formatBytes, formatTime } from './LogUtils';

interface LogRowTypedProps {
  log: Log;
  logType?: 'access' | 'error' | 'modsec';
  onClick: () => void;
}

export const LogRowTyped = memo(function LogRowTyped({ log, logType, onClick }: LogRowTypedProps) {
  if (logType === 'access') {
    return (
      <tr className="hover:bg-slate-50 dark:hover:bg-slate-700 cursor-pointer transition-colors" onClick={onClick}>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
          {formatTime(log.timestamp)}
        </td>
        <td className="px-4 py-3 text-sm text-primary-600 font-medium whitespace-nowrap max-w-[120px] truncate" title={log.host}>
          {log.host || '-'}
        </td>
        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 font-mono whitespace-nowrap">
          {log.client_ip || '-'}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <GeoIPBadge log={log} />
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          {log.request_method && <MethodBadge method={log.request_method} />}
        </td>
        <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 font-mono overflow-hidden">
          <div className="truncate" title={log.request_uri}>
            {log.request_uri || '-'}
          </div>
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          {log.status_code && <StatusCodeBadge code={log.status_code} />}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <BlockReasonBadge reason={log.block_reason} category={log.bot_category} />
        </td>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap text-right">
          {log.body_bytes_sent ? formatBytes(log.body_bytes_sent) : '-'}
        </td>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap text-right">
          {log.request_time ? `${log.request_time.toFixed(3)}s` : '-'}
        </td>
      </tr>
    );
  }

  if (logType === 'modsec') {
    return (
      <tr className="hover:bg-orange-50 dark:hover:bg-orange-900/20 cursor-pointer transition-colors" onClick={onClick}>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
          {formatTime(log.timestamp)}
        </td>
        <td className="px-4 py-3 text-sm text-orange-600 font-medium whitespace-nowrap">
          {log.host || '-'}
        </td>
        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 font-mono whitespace-nowrap">
          {log.client_ip || '-'}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className="px-2 py-0.5 bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300 rounded text-xs font-mono">
            {log.rule_id || '-'}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 truncate max-w-[120px] sm:max-w-[180px] lg:max-w-[250px] xl:max-w-[350px]" title={log.rule_message}>
          {log.rule_message || '-'}
        </td>
        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 truncate font-mono max-w-[100px] sm:max-w-[150px] lg:max-w-[180px] xl:max-w-[250px]" title={log.request_uri}>
          {log.request_uri || '-'}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
            log.action_taken === 'blocked' ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' :
            log.action_taken === 'excluded' ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
            'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300'
          }`}>
            {log.action_taken === 'excluded' ? 'pass' : log.action_taken || 'logged'}
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
      info: 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200',
      debug: 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400',
    };
    return (
      <tr className="hover:bg-red-50 dark:hover:bg-red-900/20 cursor-pointer transition-colors" onClick={onClick}>
        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
          {formatTime(log.timestamp)}
        </td>
        <td className="px-4 py-3">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityColors[log.severity || 'error'] || severityColors.error}`}>
            {log.severity || 'error'}
          </span>
        </td>
        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 font-mono whitespace-nowrap">
          {log.client_ip || '-'}
        </td>
        <td className="px-4 py-3 text-sm text-red-700 dark:text-red-400 max-w-2xl truncate" title={log.error_message}>
          {log.error_message || '-'}
        </td>
      </tr>
    );
  }

  return null;
});

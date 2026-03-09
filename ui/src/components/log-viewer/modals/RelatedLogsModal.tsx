import React, { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { useEscapeKey } from '../../../hooks/useEscapeKey';
import { fetchLogs } from '../../../api/logs';
import type { LogFilter } from '../../../types/log';
import { StatusCodeBadge, MethodBadge } from '../badges';

interface RelatedLogsModalProps {
  clientIp?: string;
  requestUri?: string;
  timestamp: string;
  host?: string;
  userAgent?: string;
  onClose: () => void;
}

export function RelatedLogsModal({ clientIp, requestUri, timestamp, host, userAgent, onClose }: RelatedLogsModalProps) {
  const { t } = useTranslation('logs');
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  useEscapeKey(onClose);

  // Calculate time range (+/- 5 seconds)
  const timeRange = useMemo(() => {
    const time = new Date(timestamp).getTime();
    return {
      start_time: new Date(time - 5000).toISOString(),
      end_time: new Date(time + 5000).toISOString()
    };
  }, [timestamp]);

  const filter: LogFilter = {
    log_type: 'access',
    client_ip: clientIp,
    uri: requestUri,
    ...timeRange
  };

  const { data, isLoading } = useQuery({
    queryKey: ['related-logs', clientIp, requestUri, timestamp],
    queryFn: () => fetchLogs(1, 50, filter),
  });

  const displayUserAgent = (userAgent && userAgent !== '-')
    ? userAgent
    : (data?.data && data.data.length > 0 ? data.data[0].http_user_agent : '-');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[60] p-4 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-5xl w-full max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            {t('detail.relatedLogsTitle', 'Related Access Logs')}
          </h3>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 bg-slate-50 dark:bg-slate-900/50 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold mb-1">{t('filters.clientIp')}</span>
              <span className="font-mono text-slate-700 dark:text-slate-200">{clientIp || '-'}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold mb-1">{t('detail.host')}</span>
              <span className="font-mono text-slate-700 dark:text-slate-200">{host || '-'}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold mb-1">{t('filters.uri')}</span>
              <span className="font-mono text-slate-700 dark:text-slate-200 truncate" title={requestUri}>
                {requestUri || '-'}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold mb-1">{t('filters.startDate')}</span>
              <span className="text-slate-700 dark:text-slate-200">{new Date(timeRange.start_time).toLocaleString()}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold mb-1">{t('filters.endDate')}</span>
              <span className="text-slate-700 dark:text-slate-200">{new Date(timeRange.end_time).toLocaleString()}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 dark:text-slate-400 uppercase font-semibold mb-1">{t('detail.userAgent')}</span>
              <span className="text-slate-700 dark:text-slate-200 truncate" title={displayUserAgent}>{displayUserAgent || '-'}</span>
            </div>
          </div>

          {isLoading ? (
            <div className="flex justify-center py-12">
              <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : !data?.data || data.data.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              {t('table.noLogs')}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="text-xs font-semibold text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700">
                    <th className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50">{t('table.columns.time')}</th>
                    <th className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50">{t('table.columns.host')}</th>
                    <th className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50">{t('table.columns.method')}</th>
                    <th className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50">{t('table.columns.path')}</th>
                    <th className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50">{t('table.columns.status')}</th>
                    <th className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50">{t('table.columns.userAgent')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                  {data.data.map((log) => (
                    <React.Fragment key={log.id}>
                      <tr
                        className={`hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors ${expandedLogId === log.id ? 'bg-slate-50 dark:bg-slate-700/50' : ''}`}
                        onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                      >
                        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">{log.host}</td>
                        <td className="px-4 py-3">
                          {log.request_method && <MethodBadge method={log.request_method} />}
                        </td>
                        <td className="px-4 py-3 text-sm font-mono text-slate-600 dark:text-slate-300 truncate max-w-[200px]" title={log.request_uri}>
                          {log.request_uri}
                        </td>
                        <td className="px-4 py-3">
                          {log.status_code && <StatusCodeBadge code={log.status_code} />}
                        </td>
                        <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                          <span className="truncate max-w-[150px] block" title={log.http_user_agent}>
                            {log.http_user_agent || '-'}
                          </span>
                        </td>
                      </tr>
                      {expandedLogId === log.id && (
                        <tr>
                          <td colSpan={6} className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-100 dark:border-slate-700">
                            <div className="text-xs space-y-4">
                              {log.raw_log ? (
                                <div>
                                  <div className="font-bold text-slate-500 dark:text-slate-400 mb-2 uppercase tracking-wider text-[10px] pl-1">{t('detail.rawLog')}</div>
                                  <pre className="bg-slate-900 text-slate-300 p-4 rounded-lg overflow-x-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed shadow-inner border border-slate-700">
                                    {log.raw_log}
                                  </pre>
                                </div>
                              ) : (
                                <div className="text-slate-500 dark:text-slate-400 italic pl-1">
                                  {t('detail.noRawLog', 'No raw log available')}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

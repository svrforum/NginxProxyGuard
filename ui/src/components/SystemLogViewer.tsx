import { useState, useEffect, useCallback, memo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  fetchSystemLogs,
  fetchSystemLogStats,
  fetchLogSources,
  type SystemLog,
  type SystemLogFilter,
} from '../api/system-logs';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useDebounce } from './log-viewer/utils';

function formatTime(timestamp: string): string {
  return new Date(timestamp).toLocaleString();
}

function LevelBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    debug: 'bg-slate-100 text-slate-600',
    info: 'bg-blue-100 text-blue-800',
    warn: 'bg-yellow-100 text-yellow-800',
    error: 'bg-red-100 text-red-800',
    fatal: 'bg-purple-100 text-purple-800',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[level] || colors.info}`}>
      {level}
    </span>
  );
}

function SourceBadge({ source }: { source: string }) {
  const { t } = useTranslation('logs');
  const colors: Record<string, string> = {
    docker_api: 'bg-green-100 text-green-800',
    docker_nginx: 'bg-blue-100 text-blue-800',
    docker_db: 'bg-purple-100 text-purple-800',
    docker_ui: 'bg-pink-100 text-pink-800',
    health_check: 'bg-slate-100 text-slate-600',
    internal: 'bg-indigo-100 text-indigo-800',
    scheduler: 'bg-orange-100 text-orange-800',
    backup: 'bg-teal-100 text-teal-800',
    certificate: 'bg-cyan-100 text-cyan-800',
  };

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[source] || 'bg-slate-100 text-slate-600'}`}>
      {t(`system.sources.${source}`) || source}
    </span>
  );
}

interface LogDetailModalProps {
  log: SystemLog;
  onClose: () => void;
}

function LogDetailModal({ log, onClose }: LogDetailModalProps) {
  const { t } = useTranslation('logs');
  useEscapeKey(onClose);
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden transition-colors">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <SourceBadge source={log.source} />
            <LevelBadge level={log.level} />
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('system.detail.title')}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 overflow-y-auto max-h-[calc(90vh-120px)]">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.detail.timestamp')}</label>
              <p className="text-sm text-slate-900 dark:text-white">{formatTime(log.created_at)}</p>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.detail.container')}</label>
              <p className="text-sm text-slate-900 dark:text-white font-mono">{log.container_name || '-'}</p>
            </div>
          </div>

          {log.component && (
            <div className="mb-4">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.detail.component')}</label>
              <p className="text-sm text-slate-900 dark:text-white">{log.component}</p>
            </div>
          )}

          <div className="mb-4">
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.detail.message')}</label>
            <pre className="text-sm text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-700/50 p-3 rounded font-mono whitespace-pre-wrap break-all">
              {log.message}
            </pre>
          </div>

          {log.details && Object.keys(log.details).length > 0 && (
            <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.detail.details')}</label>
              <pre className="text-xs text-slate-600 dark:text-slate-300 bg-slate-800 dark:bg-slate-900 text-slate-200 dark:text-slate-200 p-3 rounded mt-1 overflow-x-auto">
                {JSON.stringify(log.details, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const AUTO_REFRESH_INTERVAL = 15000;

// Isolated countdown component to prevent full SystemLogViewer re-render every second
const CountdownDisplay = memo(function CountdownDisplay({ autoRefresh, dataUpdatedAt }: { autoRefresh: boolean; dataUpdatedAt: number }) {
  const [countdown, setCountdown] = useState(AUTO_REFRESH_INTERVAL / 1000);

  useEffect(() => {
    if (dataUpdatedAt) setCountdown(AUTO_REFRESH_INTERVAL / 1000);
  }, [dataUpdatedAt]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      setCountdown((prev) => (prev <= 1 ? AUTO_REFRESH_INTERVAL / 1000 : prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [autoRefresh]);

  if (!autoRefresh) return null;
  return <span className="font-medium">{countdown}s</span>;
});

export function SystemLogViewer() {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState<SystemLogFilter>({});
  const [selectedLog, setSelectedLog] = useState<SystemLog | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 300);
  const limit = 50;

  // Apply debounced search to filter
  useEffect(() => {
    setFilter((prev) => ({ ...prev, search: debouncedSearch || undefined }));
    setOffset(0);
  }, [debouncedSearch]);

  const logsQuery = useQuery({
    queryKey: ['system-logs', offset, filter],
    queryFn: () => fetchSystemLogs(limit, offset, filter),
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
  });

  const statsQuery = useQuery({
    queryKey: ['system-log-stats'],
    queryFn: fetchSystemLogStats,
    refetchInterval: autoRefresh ? 60000 : false,
  });

  const sourcesQuery = useQuery({
    queryKey: ['log-sources'],
    queryFn: fetchLogSources,
  });

  const handleManualRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['system-logs'] });
    queryClient.invalidateQueries({ queryKey: ['system-log-stats'] });
  }, [queryClient]);

  const handleFilterChange = (key: keyof SystemLogFilter, value: string | undefined) => {
    if (key === 'search') {
      setSearchInput(value || '');
      return;
    }
    setFilter((prev) => ({ ...prev, [key]: value || undefined }));
    setOffset(0);
  };

  const totalPages = Math.ceil((logsQuery.data?.total || 0) / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.totalLogs')}</p>
          <p className="text-2xl font-bold text-slate-700 dark:text-white mt-1">
            {statsQuery.data?.total?.toLocaleString() || '0'}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
          <p className="text-xs font-medium text-blue-500 uppercase">{t('system.last24h')}</p>
          <p className="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-1">
            {statsQuery.data?.last_24h?.toLocaleString() || '0'}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
          <p className="text-xs font-medium text-red-500 uppercase">{t('system.errors')}</p>
          <p className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">
            {statsQuery.data?.by_level?.error?.toLocaleString() || '0'}
          </p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
          <p className="text-xs font-medium text-yellow-500 uppercase">{t('system.warnings')}</p>
          <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400 mt-1">
            {statsQuery.data?.by_level?.warn?.toLocaleString() || '0'}
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4 transition-colors">
        <div className="flex flex-wrap items-center gap-4">
          <select
            value={filter.source || ''}
            onChange={(e) => handleFilterChange('source', e.target.value)}
            className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="">{t('system.filters.allSources')}</option>
            {sourcesQuery.data?.map((src) => (
              <option key={src.value} value={src.value}>
                {t(`system.sources.${src.value}`) || src.label}
              </option>
            ))}
          </select>

          <select
            value={filter.level || ''}
            onChange={(e) => handleFilterChange('level', e.target.value)}
            className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="">{t('system.filters.allLevels')}</option>
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warn">Warning</option>
            <option value="error">Error</option>
            <option value="fatal">Fatal</option>
          </select>

          <input
            type="text"
            placeholder={t('system.filters.searchPlaceholder')}
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 flex-1 min-w-[200px] bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400"
          />

          <div className="flex items-center gap-2 ml-auto">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 dark:bg-slate-700/50 rounded-lg">
              <button
                onClick={() => setAutoRefresh(!autoRefresh)}
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${autoRefresh ? 'bg-primary-600' : 'bg-slate-300'
                  }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${autoRefresh ? 'translate-x-4' : 'translate-x-1'
                    }`}
                />
              </button>
              <span className="text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">
                {autoRefresh ? <CountdownDisplay autoRefresh={autoRefresh} dataUpdatedAt={logsQuery.dataUpdatedAt} /> : t('system.filters.auto')}
              </span>
            </div>

            <button
              onClick={handleManualRefresh}
              disabled={logsQuery.isFetching}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg transition-colors ${logsQuery.isFetching
                ? 'bg-slate-100 dark:bg-slate-700 text-slate-400'
                : 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 hover:bg-primary-100 dark:hover:bg-primary-900/50'
                }`}
            >
              <svg
                className={`w-4 h-4 ${logsQuery.isFetching ? 'animate-spin' : ''}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              {logsQuery.isFetching ? t('system.filters.refreshing') : t('system.filters.refresh')}
            </button>
          </div>
        </div>
      </div>

      {/* Log Table */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden transition-colors">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-700/50 border-b border-slate-200 dark:border-slate-700">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.table.time')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.table.source')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.table.level')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('system.table.message')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
              {logsQuery.isLoading ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-slate-500 dark:text-slate-400">
                    {t('system.table.loading')}
                  </td>
                </tr>
              ) : logsQuery.data?.logs?.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-slate-500 dark:text-slate-400">
                    {t('system.table.empty')}
                  </td>
                </tr>
              ) : (
                logsQuery.data?.logs?.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors"
                    onClick={() => setSelectedLog(log)}
                  >
                    <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {formatTime(log.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <SourceBadge source={log.source} />
                    </td>
                    <td className="px-4 py-3">
                      <LevelBadge level={log.level} />
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 max-w-2xl truncate font-mono">
                      {log.message.substring(0, 100)}
                      {log.message.length > 100 && '...'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200 dark:border-slate-700">
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {t('system.pagination', { current: currentPage, total: totalPages, count: logsQuery.data?.total })}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setOffset((o) => Math.max(0, o - limit))}
                disabled={offset === 0}
                className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 hover:bg-slate-50 dark:hover:bg-slate-700 dark:text-slate-300"
              >
                {t('system.previous')}
              </button>
              <button
                onClick={() => setOffset((o) => o + limit)}
                disabled={currentPage >= totalPages}
                className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 hover:bg-slate-50 dark:hover:bg-slate-700 dark:text-slate-300"
              >
                {t('system.next')}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedLog && <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

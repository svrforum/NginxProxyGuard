import { useState, useMemo } from 'react';
import { useQuery, useQueries } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import DatePicker from 'react-datepicker';
import { ko, enUS } from 'date-fns/locale';
import { fetchLogs, fetchLogStats } from '../api/logs';
import type { Log, LogFilter, BotCategory } from '../types/log';
import { HelpTip } from './common/HelpTip';
import { useEscapeKey } from '../hooks/useEscapeKey';
import { useDebounce } from './log-viewer/utils';

// Bot category display config (keys for translation)
const BOT_CATEGORY_CONFIG: Record<string, { labelKey: string; color: string; icon: string }> = {
  bad_bot: { labelKey: 'logs:botFilter.categories.badBot', color: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300', icon: '🚫' },
  ai_bot: { labelKey: 'logs:botFilter.categories.aiBot', color: 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300', icon: '🤖' },
  suspicious: { labelKey: 'logs:botFilter.categories.suspicious', color: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300', icon: '⚠️' },
  search_engine: { labelKey: 'logs:botFilter.categories.searchEngine', color: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300', icon: '🔍' },
};

function formatTime(timestamp: string, language: string = 'ko'): string {
  return new Date(timestamp).toLocaleString(language);
}


function BotCategoryBadge({ category }: { category?: BotCategory }) {
  const { t } = useTranslation('logs');
  if (!category) return <span className="text-slate-400">-</span>;
  const config = BOT_CATEGORY_CONFIG[category] || { labelKey: category, color: 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200', icon: '❓' };
  const label = config.labelKey.startsWith('logs:') ? t(config.labelKey.replace('logs:', '')) : config.labelKey;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${config.color}`}>
      <span>{config.icon}</span>
      {label}
    </span>
  );
}

function StatusCodeBadge({ code }: { code: number }) {
  let color = 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200';
  if (code >= 200 && code < 300) color = 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
  else if (code >= 300 && code < 400) color = 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
  else if (code >= 400 && code < 500) color = 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
  else if (code >= 500) color = 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {code}
    </span>
  );
}

interface LogDetailModalProps {
  log: Log;
  onClose: () => void;
}

function LogDetailModal({ log, onClose }: LogDetailModalProps) {
  const { t, i18n } = useTranslation('logs');
  useEscapeKey(onClose);
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden" onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between bg-purple-50 dark:bg-purple-900/20">
          <h3 className="text-lg font-semibold text-purple-900 dark:text-purple-100">{t('botFilter.modal.title')}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-400">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-80px)] space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.timestamp')}</label>
              <p className="text-sm text-slate-900 dark:text-white">{new Date(log.timestamp).toLocaleString(i18n.language)}</p>
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.botCategory')}</label>
              <p className="mt-1"><BotCategoryBadge category={log.bot_category} /></p>
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.clientIp')}</label>
              <p className="text-sm text-slate-900 dark:text-white font-mono">{log.client_ip || '-'}</p>
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.statusCode')}</label>
              <p className="mt-1">{log.status_code && <StatusCodeBadge code={log.status_code} />}</p>
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.host')}</label>
              <p className="text-sm text-slate-900 dark:text-white">{log.host || '-'}</p>
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.method')}</label>
              <p className="text-sm text-slate-900 dark:text-white font-mono">{log.request_method || '-'}</p>
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.requestUri')}</label>
            <p className="text-sm text-slate-900 dark:text-white font-mono break-all bg-slate-50 dark:bg-slate-700 p-2 rounded">{log.request_uri || '-'}</p>
          </div>
          <div>
            <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.userAgent')}</label>
            <p className="text-sm text-slate-900 dark:text-white font-mono break-all bg-red-50 dark:bg-red-900/20 p-2 rounded border border-red-200 dark:border-red-800">{log.http_user_agent || '-'}</p>
          </div>
          {log.raw_log && (
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium">{t('botFilter.modal.rawLog')}</label>
              <pre className="text-xs text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 p-3 rounded overflow-x-auto whitespace-pre-wrap break-all">{log.raw_log}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function BotFilterLogs() {
  const { t, i18n } = useTranslation('logs');
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [selectedLog, setSelectedLog] = useState<Log | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<BotCategory | ''>('');
  const [startDate, setStartDate] = useState<Date | null>(() => {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    d.setHours(0, 0, 0, 0);
    return d;
  });
  const [endDate, setEndDate] = useState<Date | null>(() => {
    const d = new Date();
    d.setHours(23, 59, 59, 999);
    return d;
  });
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 300);
  const dateLocale = i18n.language === 'ko' ? ko : enUS;

  const filter: LogFilter = useMemo(() => ({
    log_type: 'access',
    block_reason: 'bot_filter',
    bot_category: categoryFilter || undefined,
    start_time: startDate?.toISOString(),
    end_time: endDate?.toISOString(),
    search: debouncedSearch || undefined,
  }), [categoryFilter, startDate, endDate, debouncedSearch]);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['bot-filter-logs', filter, page, perPage],
    queryFn: () => fetchLogs(page, perPage, filter),
    refetchInterval: 15000,
  });

  // Base filter for stats (without category filter)
  const baseStatsFilter: LogFilter = useMemo(() => ({
    log_type: 'access',
    block_reason: 'bot_filter',
    start_time: startDate?.toISOString(),
    end_time: endDate?.toISOString(),
  }), [startDate, endDate]);

  // Fetch stats for each category in parallel using stats API (accurate COUNT)
  const categoryQueries = useQueries({
    queries: ['bad_bot', 'ai_bot', 'suspicious', 'search_engine'].map(cat => ({
      queryKey: ['bot-filter-stats', cat, baseStatsFilter],
      queryFn: () => fetchLogStats({ ...baseStatsFilter, bot_category: cat as BotCategory }),
      refetchInterval: 30000,
    })),
  });

  // Fetch total blocked count using stats API (accurate COUNT)
  const { data: totalData } = useQuery({
    queryKey: ['bot-filter-total', baseStatsFilter],
    queryFn: () => fetchLogStats(baseStatsFilter),
    refetchInterval: 30000,
  });

  // Build stats from queries
  const categoryStats = useMemo(() => {
    const categories = ['bad_bot', 'ai_bot', 'suspicious', 'search_engine'];
    const stats: Record<string, number> = {};
    categoryQueries.forEach((query, idx) => {
      stats[categories[idx]] = query.data?.total_logs || 0;
    });
    return stats;
  }, [categoryQueries]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
            <span className="text-xl">🤖</span>
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t('botFilter.title')}</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">{t('botFilter.subtitle')}</p>
          </div>
        </div>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {t('botFilter.refresh')}
          <HelpTip content={t('botFilter.refreshHelp')} />
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
          <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">{totalData?.total_logs || 0}</div>
          <div className="text-xs text-slate-500 dark:text-slate-400">{t('botFilter.totalBlocked')}</div>
        </div>
        {Object.entries(BOT_CATEGORY_CONFIG).map(([key, config]) => {
          const label = config.labelKey.startsWith('logs:') ? t(config.labelKey.replace('logs:', '')) : config.labelKey;
          return (
            <div key={key} className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
              <div className="text-2xl font-bold text-slate-700 dark:text-white">{categoryStats[key] || 0}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1">
                <span>{config.icon}</span> {label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
        <div className="flex flex-wrap gap-4 items-end">
          {/* Date Range */}
          <div className="flex gap-2 items-center">
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('botFilter.filters.start')}
                <HelpTip content={t('botFilter.filters.startHelp')} />
              </label>
              <DatePicker
                selected={startDate}
                onChange={setStartDate}
                showTimeSelect
                timeFormat="HH:mm"
                timeIntervals={30}
                dateFormat="MM/dd HH:mm"
                locale={dateLocale}
                className="px-3 py-1.5 border border-slate-300 rounded-lg text-sm w-36"
              />
            </div>
            <span className="text-slate-400 mt-5">~</span>
            <div>
              <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('botFilter.filters.end')}
                <HelpTip content={t('botFilter.filters.endHelp')} />
              </label>
              <DatePicker
                selected={endDate}
                onChange={setEndDate}
                showTimeSelect
                timeFormat="HH:mm"
                timeIntervals={30}
                dateFormat="MM/dd HH:mm"
                locale={dateLocale}
                className="px-3 py-1.5 border border-slate-300 rounded-lg text-sm w-36"
              />
            </div>
          </div>

          {/* Category Filter */}
          <div>
            <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('botFilter.filters.botCategory')}
              <HelpTip content={t('botFilter.filters.botCategoryHelp')} />
            </label>
            <select
              value={categoryFilter}
              onChange={e => { setCategoryFilter(e.target.value as BotCategory | ''); setPage(1); }}
              className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value="">{t('botFilter.filters.allCategories')}</option>
              <option value="bad_bot">🚫 {t('botFilter.categories.badBot')}</option>
              <option value="ai_bot">🤖 {t('botFilter.categories.aiBot')}</option>
              <option value="suspicious">⚠️ {t('botFilter.categories.suspicious')}</option>
              <option value="search_engine">🔍 {t('botFilter.categories.searchEngine')}</option>
            </select>
          </div>

          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('botFilter.filters.search')}
              <HelpTip content={t('botFilter.filters.searchHelp')} />
            </label>
            <input
              type="text"
              value={searchInput}
              onChange={e => { setSearchInput(e.target.value); setPage(1); }}
              placeholder={t('botFilter.filters.searchPlaceholder')}
              className="w-full px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
          </div>

          {/* Per Page */}
          <div>
            <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('botFilter.filters.perPage')}
              <HelpTip content={t('botFilter.filters.perPageHelp')} />
            </label>
            <select
              value={perPage}
              onChange={e => { setPerPage(Number(e.target.value)); setPage(1); }}
              className="px-3 py-1.5 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-slate-500">{t('botFilter.loading')}</div>
        ) : error ? (
          <div className="p-8 text-center text-red-500">{t('botFilter.error')}</div>
        ) : !data?.data?.length ? (
          <div className="p-8 text-center text-slate-500">
            <div className="text-4xl mb-2">🎉</div>
            <div>{t('botFilter.empty')}</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-purple-50 dark:bg-purple-900/20 border-b border-purple-100 dark:border-purple-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.time')}</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.category')}</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.clientIp')}</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.host')}</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.userAgent')}</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.uri')}</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-purple-700 dark:text-purple-300">{t('botFilter.table.status')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700">
                {data.data.map((log) => (
                  <tr
                    key={log.id}
                    className="hover:bg-purple-50 dark:hover:bg-slate-700/50 cursor-pointer transition-colors"
                    onClick={() => setSelectedLog(log)}
                  >
                    <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {formatTime(log.timestamp, i18n.language)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <BotCategoryBadge category={log.bot_category} />
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 font-mono whitespace-nowrap">
                      {log.client_ip || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 whitespace-nowrap">
                      {log.host || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-red-700 dark:text-red-400 font-mono max-w-xs truncate" title={log.http_user_agent}>
                      {log.http_user_agent || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-400 font-mono max-w-[200px] truncate" title={log.request_uri}>
                      {log.request_uri || '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {log.status_code && <StatusCodeBadge code={log.status_code} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {data && (data.has_more || page > 1) && (
          <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between bg-slate-50 dark:bg-slate-800">
            <div className="text-sm text-slate-500 dark:text-slate-400">
              {t('botFilter.pageInfo', { page: data.page, total: data.total_pages, count: data.total })}{data.has_more && '+'}
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 border border-slate-300 dark:border-slate-600 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-100 dark:hover:bg-slate-700 dark:text-slate-300"
              >
                {t('botFilter.previous')}
              </button>
              <button
                onClick={() => setPage(p => p + 1)}
                disabled={!data.has_more}
                className="px-3 py-1 border border-slate-300 dark:border-slate-600 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-100 dark:hover:bg-slate-700 dark:text-slate-300"
              >
                {t('botFilter.next')}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {
        selectedLog && (
          <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
        )
      }
    </div >
  );
}

export default BotFilterLogs;

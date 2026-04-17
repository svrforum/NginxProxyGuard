import { useTranslation } from 'react-i18next';
import type { Log, LogFilter, LogListResponse } from '../../types/log';
import type { UseQueryResult } from '@tanstack/react-query';
import { LogRowTyped, type AccessColumnKey } from './index';

const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];

interface LogTableProps {
  logType?: 'access' | 'error' | 'modsec';
  logsQuery: UseQueryResult<LogListResponse>;
  filter: LogFilter;
  page: number;
  perPage: number;
  setPage: (p: number | ((p: number) => number)) => void;
  setPerPage: (n: number) => void;
  visibleColumns: Set<AccessColumnKey>;
  onFilterChange: (f: LogFilter) => void;
  onRowSelect: (log: Log) => void;
  onClientIPClick: (ip: string) => void;
}

export function LogTable({
  logType,
  logsQuery,
  filter,
  page,
  perPage,
  setPage,
  setPerPage,
  visibleColumns,
  onFilterChange,
  onRowSelect,
  onClientIPClick,
}: LogTableProps) {
  const { t } = useTranslation('logs');

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1024px] table-fixed">
          <thead className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
            {logType === 'access' && (
              <tr>
                {visibleColumns.has('time') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[140px]">
                    {t('table.columns.time')}
                  </th>
                )}
                {visibleColumns.has('host') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[150px]">
                    {t('table.columns.host')}
                  </th>
                )}
                {visibleColumns.has('ip') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[160px]">
                    {t('table.columns.ip')}
                  </th>
                )}
                {visibleColumns.has('country') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[60px]">
                    {t('table.columns.country')}
                  </th>
                )}
                {visibleColumns.has('method') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[60px]">
                    {t('table.columns.method')}
                  </th>
                )}
                {visibleColumns.has('uri') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[200px]">
                    {t('table.columns.path')}
                  </th>
                )}
                {visibleColumns.has('status') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[55px]">
                    {t('table.columns.status')}
                  </th>
                )}
                {visibleColumns.has('block') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[85px]">
                    {t('table.columns.block')}
                  </th>
                )}
                {visibleColumns.has('size') && (
                  <th
                    className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-700 w-[65px]"
                    onClick={() =>
                      onFilterChange({
                        ...filter,
                        sort_by: 'body_bytes_sent',
                        sort_order:
                          filter.sort_by === 'body_bytes_sent' &&
                          filter.sort_order === 'desc'
                            ? 'asc'
                            : 'desc',
                      })
                    }
                  >
                    {t('table.columns.size')}{' '}
                    {filter.sort_by === 'body_bytes_sent' &&
                      (filter.sort_order === 'desc' ? '↓' : '↑')}
                  </th>
                )}
                {visibleColumns.has('responseTime') && (
                  <th
                    className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-700 w-[70px]"
                    onClick={() =>
                      onFilterChange({
                        ...filter,
                        sort_by: 'request_time',
                        sort_order:
                          filter.sort_by === 'request_time' &&
                          filter.sort_order === 'desc'
                            ? 'asc'
                            : 'desc',
                      })
                    }
                  >
                    {t('table.columns.responseTime')}{' '}
                    {filter.sort_by === 'request_time' &&
                      (filter.sort_order === 'desc' ? '↓' : '↑')}
                  </th>
                )}
                {visibleColumns.has('upstream') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[150px]">
                    {t('table.columns.upstream')}
                  </th>
                )}
                {visibleColumns.has('userAgent') && (
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[200px]">
                    {t('table.columns.userAgent')}
                  </th>
                )}
              </tr>
            )}
            {logType === 'modsec' && (
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.time')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.host')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.ip')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase w-[60px]">{t('table.columns.country')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.ruleId')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.ruleMessage')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.path')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.action')}</th>
              </tr>
            )}
            {logType === 'error' && (
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.time')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.severity')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.ip')}</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('table.columns.error')}</th>
              </tr>
            )}
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {(() => {
              // colSpan must match the rendered header cell count so the empty/loading row
              // spans the full width. Each log type has a fixed header count except access,
              // whose width is driven by the column-chooser state.
              const accessSpan = visibleColumns.size;
              const emptyColSpan =
                logType === 'access' ? accessSpan : logType === 'modsec' ? 8 : 4;
              if (logsQuery.isLoading) {
                return (
                  <tr>
                    <td
                      colSpan={emptyColSpan}
                      className="px-4 py-8 text-center text-slate-500 dark:text-slate-400"
                    >
                      {t('table.loading')}
                    </td>
                  </tr>
                );
              }
              if (logsQuery.data?.data?.length === 0) {
                return (
                  <tr>
                    <td
                      colSpan={emptyColSpan}
                      className="px-4 py-8 text-center text-slate-500 dark:text-slate-400"
                    >
                      {logType === 'modsec'
                        ? t('table.noWafEvents')
                        : logType === 'error'
                          ? t('table.noErrors')
                          : t('table.noLogs')}
                    </td>
                  </tr>
                );
              }
              return logsQuery.data?.data?.map((log) => (
                <LogRowTyped
                  key={log.id}
                  log={log}
                  logType={logType}
                  onClick={() => onRowSelect(log)}
                  onClientIPClick={onClientIPClick}
                  visibleColumns={logType === 'access' ? visibleColumns : undefined}
                />
              ));
            })()}
          </tbody>
        </table>
      </div>

      {/* Enhanced Pagination */}
      {logsQuery.data && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-4">
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {t('pagination.showing', {
                start: (page - 1) * perPage + 1,
                end: Math.min(page * perPage, logsQuery.data.total),
                total: logsQuery.data.total.toLocaleString(),
              })}
            </p>
            <div className="flex items-center gap-2">
              <label className="text-sm text-slate-500 dark:text-slate-400">
                {t('pagination.perPage')}
              </label>
              <select
                value={perPage}
                onChange={(e) => {
                  setPerPage(parseInt(e.target.value));
                  setPage(1);
                }}
                className="px-2 py-1 border border-slate-300 dark:border-slate-600 rounded text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500"
              >
                {PAGE_SIZE_OPTIONS.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(1)}
              disabled={page === 1}
              className="px-2 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300"
              title={t('pagination.first')}
            >
              «
            </button>
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300"
            >
              {t('pagination.previous')}
            </button>
            <span className="px-3 py-1 text-sm text-slate-600 dark:text-slate-300">
              {t('pagination.page', {
                current: page,
                total: logsQuery.data.total_pages,
              })}
              {logsQuery.data.has_more && '+'}
            </span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={!logsQuery.data.has_more}
              className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300"
            >
              {t('pagination.next')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

import React from 'react';
import { useTranslation } from 'react-i18next';
import type { UseQueryResult } from '@tanstack/react-query';
import type { LogStats } from '../../types/log';
import { VisualizationPanel, ColumnChooser, type AccessColumnKey } from './index';

interface LogToolbarProps {
  logType?: 'access' | 'error' | 'modsec';
  statsQuery: UseQueryResult<LogStats>;
  showVisualization: boolean;
  setShowVisualization: (v: boolean) => void;
  searchInput: string;
  setSearchInput: (v: string) => void;
  showAdvancedFilters: boolean;
  setShowAdvancedFilters: (v: boolean) => void;
  activeFilterCount: number;
  autoRefresh: boolean;
  setAutoRefresh: (v: boolean) => void;
  countdownRef: React.MutableRefObject<number>;
  countdownElRef: React.RefObject<HTMLSpanElement | null>;
  handleManualRefresh: () => void;
  logsFetching: boolean;
  lastRefreshLocaleTime: string;
  visibleColumns: Set<AccessColumnKey>;
  toggleColumn: (col: AccessColumnKey) => void;
  resetColumns: () => void;
  setShowSettings: (v: boolean) => void;
}

export function LogToolbar({
  logType,
  statsQuery,
  showVisualization,
  setShowVisualization,
  searchInput,
  setSearchInput,
  showAdvancedFilters,
  setShowAdvancedFilters,
  activeFilterCount,
  autoRefresh,
  setAutoRefresh,
  countdownRef,
  countdownElRef,
  handleManualRefresh,
  logsFetching,
  lastRefreshLocaleTime,
  visibleColumns,
  toggleColumn,
  resetColumns,
  setShowSettings,
}: LogToolbarProps) {
  const { t } = useTranslation('logs');

  return (
    <>
      {/* Visualization Toggle */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => setShowVisualization(!showVisualization)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            showVisualization
              ? 'bg-primary-600 text-white shadow-md'
              : 'bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700'
          }`}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          {showVisualization ? t('viewer.hideCharts') : t('viewer.showCharts')}
          <svg className={`w-4 h-4 transition-transform ${showVisualization ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        {/* Summary Stats */}
        <div className="flex items-center gap-4 text-sm">
          <span className="text-slate-500 dark:text-slate-400">
            {t('stats.total')}:{' '}
            <span className="font-semibold text-slate-700 dark:text-slate-300">
              {statsQuery.data?.total_logs?.toLocaleString() || 0}
            </span>
          </span>
          {logType === 'access' && (
            <span className="text-blue-500">
              {t('stats.access')}:{' '}
              <span className="font-semibold">
                {statsQuery.data?.access_logs?.toLocaleString() || 0}
              </span>
            </span>
          )}
          {logType === 'modsec' && (
            <span className="text-orange-500">
              {t('stats.waf')}:{' '}
              <span className="font-semibold">
                {statsQuery.data?.modsec_logs?.toLocaleString() || 0}
              </span>
            </span>
          )}
          {logType === 'error' && (
            <span className="text-red-500">
              {t('stats.errors')}:{' '}
              <span className="font-semibold">
                {statsQuery.data?.error_logs?.toLocaleString() || 0}
              </span>
            </span>
          )}
        </div>
      </div>

      {/* Visualization Panel */}
      {showVisualization && (
        <VisualizationPanel
          stats={statsQuery.data}
          logType={logType}
          isLoading={statsQuery.isLoading}
        />
      )}

      {/* Stats Cards */}
      {logType === 'access' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-blue-500 uppercase">
              {t('stats.totalRequests')}
            </p>
            <p className="text-2xl font-bold text-blue-600 dark:text-blue-500 mt-1">
              {statsQuery.data?.access_logs.toLocaleString() || '0'}
            </p>
          </div>
          {statsQuery.data?.top_status_codes?.slice(0, 3).map((stat) => (
            <div
              key={stat.status_code}
              className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4"
            >
              <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">
                {t('stats.status', { code: stat.status_code })}
              </p>
              <p
                className={`text-2xl font-bold mt-1 ${
                  stat.status_code >= 500
                    ? 'text-red-600 dark:text-red-400'
                    : stat.status_code >= 400
                      ? 'text-yellow-600 dark:text-yellow-400'
                      : stat.status_code >= 300
                        ? 'text-blue-600 dark:text-blue-400'
                        : 'text-green-600 dark:text-green-400'
                }`}
              >
                {stat.count.toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}

      {logType === 'modsec' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-orange-500 uppercase">
              {t('stats.wafEvents')}
            </p>
            <p className="text-2xl font-bold text-orange-600 dark:text-orange-500 mt-1">
              {statsQuery.data?.modsec_logs.toLocaleString() || '0'}
            </p>
          </div>
          {statsQuery.data?.top_rule_ids?.slice(0, 3).map((stat) => (
            <div
              key={stat.rule_id}
              className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4"
            >
              <p
                className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase truncate"
                title={stat.message}
              >
                {t('stats.rule', { id: stat.rule_id })}
              </p>
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-500 mt-1">
                {stat.count.toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}

      {logType === 'error' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-red-500 uppercase">
              {t('stats.errorLogs')}
            </p>
            <p className="text-2xl font-bold text-red-600 dark:text-red-500 mt-1">
              {statsQuery.data?.error_logs.toLocaleString() || '0'}
            </p>
          </div>
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Quick Search */}
          <div className="flex-1 min-w-[200px]">
            <input
              type="text"
              placeholder={
                logType === 'modsec'
                  ? t('filters.searchWaf')
                  : logType === 'error'
                    ? t('filters.searchError')
                    : t('filters.uriPlaceholder')
              }
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
            />
          </div>

          {/* Advanced Filters Toggle */}
          <button
            onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              showAdvancedFilters || activeFilterCount > 0
                ? 'bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300'
                : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
            }`}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" />
            </svg>
            {t('viewer.filters')}
            {activeFilterCount > 0 && (
              <span className="px-1.5 py-0.5 bg-primary-600 text-white rounded-full text-xs">
                {activeFilterCount}
              </span>
            )}
          </button>

          {/* Auto-refresh toggle */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 dark:bg-slate-700 rounded-lg text-slate-600 dark:text-slate-300">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                autoRefresh
                  ? 'bg-primary-600'
                  : 'bg-slate-300 dark:bg-slate-500'
              }`}
              title={
                autoRefresh
                  ? t('viewer.autoRefreshOn')
                  : t('viewer.autoRefreshOff')
              }
            >
              <span
                className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                  autoRefresh ? 'translate-x-4' : 'translate-x-1'
                }`}
              />
            </button>
            <span className="text-xs text-slate-600 dark:text-slate-300 whitespace-nowrap">
              {autoRefresh ? (
                <span ref={countdownElRef} className="font-medium">{countdownRef.current}s</span>
              ) : (
                'Auto'
              )}
            </span>
          </div>

          {/* Refresh button */}
          <button
            onClick={handleManualRefresh}
            disabled={logsFetching}
            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
              logsFetching
                ? 'bg-slate-100 dark:bg-slate-700 text-slate-400 dark:text-slate-500 cursor-not-allowed'
                : 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/50'
            }`}
            title={t('viewer.lastUpdated', { time: lastRefreshLocaleTime })}
          >
            <svg
              className={`w-4 h-4 ${logsFetching ? 'animate-spin' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>

          {/* Column Chooser (access log only) */}
          {logType === 'access' && (
            <ColumnChooser
              visible={visibleColumns}
              onToggle={toggleColumn}
              onReset={resetColumns}
            />
          )}

          {/* Settings */}
          <button
            onClick={() => setShowSettings(true)}
            className="p-2 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
            title={t('viewer.settings')}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
        </div>
      </div>
    </>
  );
}

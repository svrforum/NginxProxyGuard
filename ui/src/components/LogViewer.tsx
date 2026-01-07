import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { fetchLogs, fetchLogStats, fetchLogSettings } from "../api/logs";
import type { Log, LogType, LogFilter, BlockReason } from "../types/log";

// Import extracted components
import {
  useDebounce,
  getDefaultDateRange,
  VisualizationPanel,
  AdvancedFilterPanel,
  LogDetailModal,
  SettingsModal,
  ActiveFilterTags,
  LogRowTyped,
} from "./log-viewer";

interface LogViewerProps {
  logType?: "access" | "error" | "modsec";
  defaultBlockReason?: BlockReason;
}

const AUTO_REFRESH_INTERVAL = 5000;
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];

export function LogViewer({ logType, defaultBlockReason }: LogViewerProps) {
  const { t, i18n } = useTranslation("logs");
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [filter, setFilter] = useState<LogFilter>(() => {
    // Start with default date range
    const initialFilter: LogFilter = {
      ...getDefaultDateRange(),
      ...(defaultBlockReason ? { block_reason: defaultBlockReason } : {}),
    };

    // Override with URL parameters if present
    if (searchParams.get("start_time"))
      initialFilter.start_time = searchParams.get("start_time") || undefined;
    if (searchParams.get("end_time"))
      initialFilter.end_time = searchParams.get("end_time") || undefined;
    if (searchParams.get("client_ip"))
      initialFilter.client_ip = searchParams.get("client_ip") || undefined;
    if (searchParams.get("host"))
      initialFilter.host = searchParams.get("host") || undefined;
    if (searchParams.get("uri"))
      initialFilter.uri = searchParams.get("uri") || undefined;

    return initialFilter;
  });
  const [selectedLog, setSelectedLog] = useState<Log | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [showVisualization, setShowVisualization] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [countdown, setCountdown] = useState(AUTO_REFRESH_INTERVAL / 1000);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [searchInput, setSearchInput] = useState("");

  // Debounce search input
  const debouncedSearch = useDebounce(searchInput, 300);

  // Reset page and filter when logType or defaultBlockReason changes
  React.useEffect(() => {
    setPage(1);
    setFilter((prev) => ({
      ...prev,
      block_reason: defaultBlockReason || undefined,
    }));
  }, [logType, defaultBlockReason]);

  // Apply debounced search to filter
  useEffect(() => {
    setFilter((prev) => ({
      ...prev,
      search: debouncedSearch || undefined,
    }));
    setPage(1);
  }, [debouncedSearch]);

  const effectiveFilter: LogFilter = useMemo(
    () => ({
      ...filter,
      log_type: logType as LogType,
    }),
    [filter, logType]
  );

  // Count active filters
  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (filter.start_time) count++;
    if (filter.end_time) count++;
    // Array filters (new multi-select)
    if (filter.hosts?.length) count++;
    if (filter.client_ips?.length) count++;
    if (filter.uris?.length) count++;
    if (filter.user_agents?.length) count++;
    // Legacy single-value filters (for backward compatibility)
    if (filter.host) count++;
    if (filter.client_ip) count++;
    if (filter.uri) count++;
    if (filter.user_agent) count++;
    // Other filters
    if (filter.method) count++;
    if (filter.geo_country_code) count++;
    if (filter.status_codes?.length) count++;
    if (filter.min_size) count++;
    if (filter.max_size) count++;
    if (filter.min_request_time) count++;
    if (filter.block_reason) count++;
    if (filter.bot_category) count++;
    // Exclude filters
    if (filter.exclude_ips?.length) count++;
    if (filter.exclude_user_agents?.length) count++;
    if (filter.exclude_uris?.length) count++;
    if (filter.exclude_hosts?.length) count++;
    if (filter.exclude_countries?.length) count++;
    return count;
  }, [filter]);

  // Serialize filter for queryKey to ensure React Query detects changes
  const filterKey = JSON.stringify(effectiveFilter);

  const logsQuery = useQuery({
    queryKey: ["logs", page, perPage, filterKey],
    queryFn: () => fetchLogs(page, perPage, effectiveFilter),
    refetchInterval: autoRefresh ? AUTO_REFRESH_INTERVAL : false,
  });

  const statsQuery = useQuery({
    queryKey: ["log-stats", filterKey],
    queryFn: () => fetchLogStats(effectiveFilter),
    refetchInterval: autoRefresh ? 10000 : false,
  });

  const settingsQuery = useQuery({
    queryKey: ["log-settings"],
    queryFn: fetchLogSettings,
  });

  useEffect(() => {
    if (logsQuery.dataUpdatedAt) {
      setLastRefresh(new Date(logsQuery.dataUpdatedAt));
      setCountdown(AUTO_REFRESH_INTERVAL / 1000);
    }
  }, [logsQuery.dataUpdatedAt]);

  useEffect(() => {
    if (!autoRefresh) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) return AUTO_REFRESH_INTERVAL / 1000;
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [autoRefresh]);

  const handleManualRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ["logs"] });
    queryClient.invalidateQueries({ queryKey: ["log-stats"] });
    setLastRefresh(new Date());
    setCountdown(AUTO_REFRESH_INTERVAL / 1000);
  }, [queryClient]);

  const handleFilterChange = useCallback((newFilter: LogFilter) => {
    setFilter(newFilter);
    setPage(1);
  }, []);

  const handleRemoveFilter = useCallback((key: keyof LogFilter) => {
    setFilter((prev) => {
      const newFilter = { ...prev };
      delete newFilter[key];
      return newFilter;
    });
    setPage(1);
  }, []);

  return (
    <div className="space-y-4">
      {/* Visualization Toggle */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => setShowVisualization(!showVisualization)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            showVisualization
              ? "bg-primary-600 text-white shadow-md"
              : "bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700"
          }`}
        >
          <svg
            className="w-5 h-5"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
            />
          </svg>
          {showVisualization ? t("viewer.hideCharts") : t("viewer.showCharts")}
          <svg
            className={`w-4 h-4 transition-transform ${
              showVisualization ? "rotate-180" : ""
            }`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 9l-7 7-7-7"
            />
          </svg>
        </button>

        {/* Summary Stats */}
        <div className="flex items-center gap-4 text-sm">
          <span className="text-slate-500">
            {t("stats.total")}:{" "}
            <span className="font-semibold text-slate-700">
              {statsQuery.data?.total_logs?.toLocaleString() || 0}
            </span>
          </span>
          {logType === "access" && (
            <span className="text-blue-500">
              {t("stats.access")}:{" "}
              <span className="font-semibold">
                {statsQuery.data?.access_logs?.toLocaleString() || 0}
              </span>
            </span>
          )}
          {logType === "modsec" && (
            <span className="text-orange-500">
              {t("stats.waf")}:{" "}
              <span className="font-semibold">
                {statsQuery.data?.modsec_logs?.toLocaleString() || 0}
              </span>
            </span>
          )}
          {logType === "error" && (
            <span className="text-red-500">
              {t("stats.errors")}:{" "}
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
      {logType === "access" && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-blue-500 uppercase">
              {t("stats.totalRequests")}
            </p>
            <p className="text-2xl font-bold text-blue-600 dark:text-blue-500 mt-1">
              {statsQuery.data?.access_logs.toLocaleString() || "0"}
            </p>
          </div>
          {statsQuery.data?.top_status_codes?.slice(0, 3).map((stat) => (
            <div
              key={stat.status_code}
              className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4"
            >
              <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">
                {t("stats.status", { code: stat.status_code })}
              </p>
              <p
                className={`text-2xl font-bold mt-1 ${
                  stat.status_code >= 500
                    ? "text-red-600 dark:text-red-400"
                    : stat.status_code >= 400
                    ? "text-yellow-600 dark:text-yellow-400"
                    : stat.status_code >= 300
                    ? "text-blue-600 dark:text-blue-400"
                    : "text-green-600 dark:text-green-400"
                }`}
              >
                {stat.count.toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}

      {logType === "modsec" && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-orange-500 uppercase">
              {t("stats.wafEvents")}
            </p>
            <p className="text-2xl font-bold text-orange-600 dark:text-orange-500 mt-1">
              {statsQuery.data?.modsec_logs.toLocaleString() || "0"}
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
                {t("stats.rule", { id: stat.rule_id })}
              </p>
              <p className="text-2xl font-bold text-orange-600 dark:text-orange-500 mt-1">
                {stat.count.toLocaleString()}
              </p>
            </div>
          ))}
        </div>
      )}

      {logType === "error" && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-red-500 uppercase">
              {t("stats.errorLogs")}
            </p>
            <p className="text-2xl font-bold text-red-600 dark:text-red-500 mt-1">
              {statsQuery.data?.error_logs.toLocaleString() || "0"}
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
                logType === "modsec"
                  ? t("filters.searchWaf")
                  : logType === "error"
                  ? t("filters.searchError")
                  : t("filters.uriPlaceholder")
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
                ? "bg-primary-100 text-primary-700"
                : "bg-slate-100 text-slate-600 hover:bg-slate-200"
            }`}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"
              />
            </svg>
            {t("viewer.filters")}
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
                  ? "bg-primary-600"
                  : "bg-slate-300 dark:bg-slate-500"
              }`}
              title={
                autoRefresh
                  ? t("viewer.autoRefreshOn")
                  : t("viewer.autoRefreshOff")
              }
            >
              <span
                className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                  autoRefresh ? "translate-x-4" : "translate-x-1"
                }`}
              />
            </button>
            <span className="text-xs text-slate-600 dark:text-slate-300 whitespace-nowrap">
              {autoRefresh ? (
                <span className="font-medium">{countdown}s</span>
              ) : (
                "Auto"
              )}
            </span>
          </div>

          {/* Refresh button */}
          <button
            onClick={handleManualRefresh}
            disabled={logsQuery.isFetching}
            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
              logsQuery.isFetching
                ? "bg-slate-100 dark:bg-slate-700 text-slate-400 dark:text-slate-500 cursor-not-allowed"
                : "bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/50"
            }`}
            title={t("viewer.lastUpdated", {
              time: lastRefresh.toLocaleTimeString(i18n.language),
            })}
          >
            <svg
              className={`w-4 h-4 ${
                logsQuery.isFetching ? "animate-spin" : ""
              }`}
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
          </button>

          {/* Settings */}
          <button
            onClick={() => setShowSettings(true)}
            className="p-2 text-slate-500 hover:bg-slate-100 rounded-lg transition-colors"
            title={t("viewer.settings")}
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
              />
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
              />
            </svg>
          </button>
        </div>
      </div>

      {/* Advanced Filters Panel */}
      {showAdvancedFilters && (
        <AdvancedFilterPanel
          filter={filter}
          onFilterChange={handleFilterChange}
          logType={logType}
          onClose={() => setShowAdvancedFilters(false)}
        />
      )}

      {/* Active Filter Tags */}
      <ActiveFilterTags filter={filter} onRemove={handleRemoveFilter} />

      {/* Log Table */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1024px] table-fixed">
            <thead className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
              {logType === "access" && (
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[140px]">
                    {t("table.columns.time")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[180px]">
                    {t("table.columns.host")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[120px]">
                    {t("table.columns.ip")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[60px]">
                    {t("table.columns.country")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[60px]">
                    {t("table.columns.method")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[200px]">
                    {t("table.columns.path")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[55px]">
                    {t("table.columns.status")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[85px]">
                    {t("table.columns.block")}
                  </th>
                  <th
                    className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase cursor-pointer hover:bg-slate-100 w-[65px]"
                    onClick={() =>
                      handleFilterChange({
                        ...filter,
                        sort_by: "body_bytes_sent",
                        sort_order:
                          filter.sort_by === "body_bytes_sent" &&
                          filter.sort_order === "desc"
                            ? "asc"
                            : "desc",
                      })
                    }
                  >
                    {t("table.columns.size")}{" "}
                    {filter.sort_by === "body_bytes_sent" &&
                      (filter.sort_order === "desc" ? "↓" : "↑")}
                  </th>
                  <th
                    className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase cursor-pointer hover:bg-slate-100 w-[70px]"
                    onClick={() =>
                      handleFilterChange({
                        ...filter,
                        sort_by: "request_time",
                        sort_order:
                          filter.sort_by === "request_time" &&
                          filter.sort_order === "desc"
                            ? "asc"
                            : "desc",
                      })
                    }
                  >
                    {t("table.columns.responseTime")}{" "}
                    {filter.sort_by === "request_time" &&
                      (filter.sort_order === "desc" ? "↓" : "↑")}
                  </th>
                </tr>
              )}
              {logType === "modsec" && (
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.time")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.host")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.ip")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase w-[60px]">
                    {t("table.columns.country")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.ruleId")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.ruleMessage")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.path")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.action")}
                  </th>
                </tr>
              )}
              {logType === "error" && (
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.time")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.severity")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.ip")}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">
                    {t("table.columns.error")}
                  </th>
                </tr>
              )}
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {logsQuery.isLoading ? (
                <tr>
                  <td
                    colSpan={10}
                    className="px-4 py-8 text-center text-slate-500"
                  >
                    {t("table.loading")}
                  </td>
                </tr>
              ) : logsQuery.data?.data?.length === 0 ? (
                <tr>
                  <td
                    colSpan={10}
                    className="px-4 py-8 text-center text-slate-500"
                  >
                    {logType === "modsec"
                      ? t("table.noWafEvents")
                      : logType === "error"
                      ? t("table.noErrors")
                      : t("table.noLogs")}
                  </td>
                </tr>
              ) : (
                logsQuery.data?.data?.map((log) => (
                  <LogRowTyped
                    key={log.id}
                    log={log}
                    logType={logType}
                    onClick={() => setSelectedLog(log)}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Enhanced Pagination */}
        {logsQuery.data && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200 dark:border-slate-700">
            <div className="flex items-center gap-4">
              <p className="text-sm text-slate-500">
                {t("pagination.showing", {
                  start: (page - 1) * perPage + 1,
                  end: Math.min(page * perPage, logsQuery.data.total),
                  total: logsQuery.data.total.toLocaleString(),
                })}
              </p>
              <div className="flex items-center gap-2">
                <label className="text-sm text-slate-500">
                  {t("pagination.perPage")}
                </label>
                <select
                  value={perPage}
                  onChange={(e) => {
                    setPerPage(parseInt(e.target.value));
                    setPage(1);
                  }}
                  className="px-2 py-1 border border-slate-300 rounded text-sm focus:ring-2 focus:ring-primary-500"
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
                title={t("pagination.first")}
              >
                «
              </button>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300"
              >
                {t("pagination.previous")}
              </button>
              <span className="px-3 py-1 text-sm text-slate-600 dark:text-slate-300">
                {t("pagination.page", {
                  current: page,
                  total: logsQuery.data.total_pages,
                })}
              </span>
              <button
                onClick={() =>
                  setPage((p) => Math.min(logsQuery.data!.total_pages, p + 1))
                }
                disabled={page === logsQuery.data.total_pages}
                className="px-3 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300"
              >
                {t("pagination.next")}
              </button>
              <button
                onClick={() => setPage(logsQuery.data!.total_pages)}
                disabled={page === logsQuery.data.total_pages}
                className="px-2 py-1 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300"
                title={t("pagination.last")}
              >
                »
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {selectedLog && (
        <LogDetailModal
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
          onRuleDisabled={() => {
            queryClient.invalidateQueries({ queryKey: ["waf-rules"] });
            queryClient.invalidateQueries({ queryKey: ["waf-hosts"] });
          }}
        />
      )}

      {showSettings && settingsQuery.data && (
        <SettingsModal
          settings={settingsQuery.data}
          onClose={() => setShowSettings(false)}
        />
      )}
    </div>
  );
}

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { fetchLogs, fetchLogStats, fetchLogSettings } from '../../api/logs';
import type { LogFilter, LogType, BlockReason } from '../../types/log';
import { useDebounce, getDefaultDateRange } from './utils';
import { usePageVisibility } from '../../hooks/usePageVisibility';

export const AUTO_REFRESH_INTERVAL = 15000;

interface UseLogQueryArgs {
  logType?: 'access' | 'error' | 'modsec';
  defaultBlockReason?: BlockReason;
}

// Central data + filter state for the log viewer.
// Exposes filter setters, query results, auto-refresh handles and a manual
// refresh callback so the presentational pieces stay dumb.
export function useLogQuery({ logType, defaultBlockReason }: UseLogQueryArgs) {
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(50);
  const [filter, setFilter] = useState<LogFilter>(() => {
    const initialFilter: LogFilter = {
      ...getDefaultDateRange(),
      ...(defaultBlockReason ? { block_reason: defaultBlockReason } : {}),
    };

    if (searchParams.get('start_time')) initialFilter.start_time = searchParams.get('start_time') || undefined;
    if (searchParams.get('end_time')) initialFilter.end_time = searchParams.get('end_time') || undefined;
    if (searchParams.get('client_ip')) initialFilter.client_ip = searchParams.get('client_ip') || undefined;
    if (searchParams.get('host')) initialFilter.host = searchParams.get('host') || undefined;
    if (searchParams.get('uri')) initialFilter.uri = searchParams.get('uri') || undefined;

    return initialFilter;
  });
  const [autoRefresh, setAutoRefresh] = useState(true);
  const isVisible = usePageVisibility();
  // Pause polling on hidden tabs. React Query keeps the cache warm so the
  // user sees fresh data on return; the next refetch fires automatically.
  const shouldPoll = autoRefresh && isVisible;
  // Cursor for keyset pagination. Held alongside `page` for the legacy
  // OFFSET fallback — the backend uses cursor when set, otherwise OFFSET.
  // Cleared on filter/sort/perPage change and on "Previous"/"First" so the
  // user always sees consistent rows.
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const countdownRef = useRef(AUTO_REFRESH_INTERVAL / 1000);
  const countdownElRef = useRef<HTMLSpanElement>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebounce(searchInput, 300);

  // Reset page and filter when logType or defaultBlockReason changes
  useEffect(() => {
    setPage(1);
    setCursor(undefined);
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
    setCursor(undefined);
  }, [debouncedSearch]);

  const effectiveFilter: LogFilter = useMemo(
    () => ({
      ...filter,
      log_type: logType as LogType,
    }),
    [filter, logType]
  );

  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (filter.start_time) count++;
    if (filter.end_time) count++;
    if (filter.hosts?.length) count++;
    if (filter.client_ips?.length) count++;
    if (filter.uris?.length) count++;
    if (filter.user_agents?.length) count++;
    if (filter.host) count++;
    if (filter.client_ip) count++;
    if (filter.uri) count++;
    if (filter.user_agent) count++;
    if (filter.method) count++;
    if (filter.geo_country_code) count++;
    if (filter.status_codes?.length) count++;
    if (filter.min_size) count++;
    if (filter.max_size) count++;
    if (filter.min_request_time) count++;
    if (filter.block_reason) count++;
    if (filter.bot_category) count++;
    if (filter.exclude_ips?.length) count++;
    if (filter.exclude_user_agents?.length) count++;
    if (filter.exclude_uris?.length) count++;
    if (filter.exclude_hosts?.length) count++;
    if (filter.exclude_countries?.length) count++;
    return count;
  }, [filter]);

  const filterKey = useMemo(() => JSON.stringify(effectiveFilter), [effectiveFilter]);

  const logsQuery = useQuery({
    queryKey: ['logs', page, perPage, filterKey, cursor],
    queryFn: () => fetchLogs(page, perPage, effectiveFilter, cursor),
    refetchInterval: shouldPoll ? AUTO_REFRESH_INTERVAL : false,
  });

  const statsQuery = useQuery({
    queryKey: ['log-stats', filterKey],
    queryFn: () => fetchLogStats(effectiveFilter),
    refetchInterval: shouldPoll ? 60000 : false,
  });

  const settingsQuery = useQuery({
    queryKey: ['log-settings'],
    queryFn: fetchLogSettings,
  });

  useEffect(() => {
    if (logsQuery.dataUpdatedAt) {
      setLastRefresh(new Date(logsQuery.dataUpdatedAt));
      if (autoRefresh) {
        countdownRef.current = AUTO_REFRESH_INTERVAL / 1000;
        if (countdownElRef.current) {
          countdownElRef.current.textContent = `${countdownRef.current}s`;
        }
      }
    }
  }, [logsQuery.dataUpdatedAt, autoRefresh]);

  useEffect(() => {
    if (!autoRefresh) return;

    const timer = setInterval(() => {
      countdownRef.current = countdownRef.current <= 1
        ? AUTO_REFRESH_INTERVAL / 1000
        : countdownRef.current - 1;
      if (countdownElRef.current) {
        countdownElRef.current.textContent = `${countdownRef.current}s`;
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [autoRefresh]);

  const handleManualRefresh = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['logs'] });
    queryClient.invalidateQueries({ queryKey: ['log-stats'] });
    setLastRefresh(new Date());
    countdownRef.current = AUTO_REFRESH_INTERVAL / 1000;
    if (countdownElRef.current) {
      countdownElRef.current.textContent = `${countdownRef.current}s`;
    }
  }, [queryClient]);

  const handleFilterChange = useCallback((newFilter: LogFilter) => {
    setFilter(newFilter);
    setPage(1);
    setCursor(undefined);
  }, []);

  const handleRemoveFilter = useCallback((key: keyof LogFilter) => {
    setFilter((prev) => {
      const newFilter = { ...prev };
      delete newFilter[key];
      return newFilter;
    });
    setPage(1);
    setCursor(undefined);
  }, []);

  const handleClientIPClick = useCallback((ip: string) => {
    setFilter((prev) => {
      if (prev.client_ip === ip) {
        const next = { ...prev };
        delete next.client_ip;
        return next;
      }
      const next = { ...prev, client_ip: ip };
      delete next.client_ips;
      return next;
    });
    setPage(1);
    setCursor(undefined);
  }, []);

  // Sequential "Next" navigation — uses the cursor returned with the current
  // page so the DB skips OFFSET work entirely. Deep pages (1000+) drop from
  // multiple seconds to under 100ms.
  const goToNextPage = useCallback(() => {
    const next = logsQuery.data?.next_cursor;
    setPage((p) => p + 1);
    setCursor(next);
  }, [logsQuery.data?.next_cursor]);

  // Backwards navigation. Cursor pagination is forward-only without a
  // history stack, so step back to OFFSET. Acceptable cost — Previous on
  // a deep page is rare and the OFFSET there is bounded by the page number.
  const goToPrevPage = useCallback(() => {
    setPage((p) => Math.max(1, p - 1));
    setCursor(undefined);
  }, []);

  const goToFirstPage = useCallback(() => {
    setPage(1);
    setCursor(undefined);
  }, []);

  return {
    // state
    page,
    setPage,
    perPage,
    setPerPage,
    filter,
    searchInput,
    setSearchInput,
    autoRefresh,
    setAutoRefresh,
    lastRefresh,
    countdownRef,
    countdownElRef,
    activeFilterCount,
    // queries
    logsQuery,
    statsQuery,
    settingsQuery,
    // handlers
    handleManualRefresh,
    handleFilterChange,
    handleRemoveFilter,
    handleClientIPClick,
    goToNextPage,
    goToPrevPage,
    goToFirstPage,
    queryClient,
  };
}

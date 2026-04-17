import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Log, BlockReason } from "../types/log";

import {
  AdvancedFilterPanel,
  LogDetailModal,
  SettingsModal,
  ActiveFilterTags,
  useAccessColumnVisibility,
} from "./log-viewer";
import { useLogQuery } from "./log-viewer/useLogQuery";
import { LogToolbar } from "./log-viewer/LogToolbar";
import { LogTable } from "./log-viewer/LogTable";

interface LogViewerProps {
  logType?: "access" | "error" | "modsec";
  defaultBlockReason?: BlockReason;
}

export function LogViewer({ logType, defaultBlockReason }: LogViewerProps) {
  const { i18n } = useTranslation("logs");
  const [selectedLog, setSelectedLog] = useState<Log | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [showVisualization, setShowVisualization] = useState(false);
  const { visible: visibleColumns, toggle: toggleColumn, reset: resetColumns } = useAccessColumnVisibility();

  const {
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
    logsQuery,
    statsQuery,
    settingsQuery,
    handleManualRefresh,
    handleFilterChange,
    handleRemoveFilter,
    handleClientIPClick,
    queryClient,
  } = useLogQuery({ logType, defaultBlockReason });

  return (
    <div className="space-y-4">
      <LogToolbar
        logType={logType}
        statsQuery={statsQuery}
        showVisualization={showVisualization}
        setShowVisualization={setShowVisualization}
        searchInput={searchInput}
        setSearchInput={setSearchInput}
        showAdvancedFilters={showAdvancedFilters}
        setShowAdvancedFilters={setShowAdvancedFilters}
        activeFilterCount={activeFilterCount}
        autoRefresh={autoRefresh}
        setAutoRefresh={setAutoRefresh}
        countdownRef={countdownRef}
        countdownElRef={countdownElRef}
        handleManualRefresh={handleManualRefresh}
        logsFetching={logsQuery.isFetching}
        lastRefreshLocaleTime={lastRefresh.toLocaleTimeString(i18n.language)}
        visibleColumns={visibleColumns}
        toggleColumn={toggleColumn}
        resetColumns={resetColumns}
        setShowSettings={setShowSettings}
      />

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
      <LogTable
        logType={logType}
        logsQuery={logsQuery}
        filter={filter}
        page={page}
        perPage={perPage}
        setPage={setPage}
        setPerPage={setPerPage}
        visibleColumns={visibleColumns}
        onFilterChange={handleFilterChange}
        onRowSelect={setSelectedLog}
        onClientIPClick={handleClientIPClick}
      />

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

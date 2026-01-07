import type { Log, LogType, LogFilter, LogSettings, LogStats, CountryStat, BlockReason, BotCategory } from '../../types/log';

export type { Log, LogType, LogFilter, LogSettings, LogStats, CountryStat, BlockReason, BotCategory };

export interface BarChartProps {
  data: { label: string; value: number; color?: string }[];
  title: string;
  maxItems?: number;
}

export interface StatusCodeChartProps {
  data: { status_code: number; count: number }[];
}

export interface VisualizationPanelProps {
  stats: LogStats | undefined;
  logType?: LogType;
  isLoading: boolean;
}

export interface TagInputProps {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder: string;
  fetchSuggestions?: (search: string) => Promise<string[]>;
  className?: string;
  helpText?: string;
}

export interface AdvancedFilterPanelProps {
  filter: LogFilter;
  onFilterChange: (filter: LogFilter) => void;
  onClose: () => void;
  onApply: () => void;
}

export interface ActiveFilterTagsProps {
  filter: LogFilter;
  onFilterChange: (filter: LogFilter) => void;
}

export interface LogRowTypedProps {
  log: Log;
  onClick: () => void;
  isExpanded?: boolean;
}

export interface RelatedLogsModalProps {
  isOpen: boolean;
  onClose: () => void;
  log: Log;
  accessLogs: Log[];
  isLoading: boolean;
  onLogClick: (log: Log) => void;
}

export interface LogDetailModalProps {
  log: Log | null;
  onClose: () => void;
}

export interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export interface LogViewerProps {
  logType?: LogType;
  embedded?: boolean;
}

export const AUTO_REFRESH_INTERVAL = 5000;
export const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];

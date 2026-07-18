import { apiGet, apiPost, apiDelete } from './client'
import type { LogFilter } from '../types/log'

// A saved, named set of log-viewer filters (#210).
export interface LogFilterPreset {
  id: string
  name: string
  log_type: string
  filter: LogFilter
  created_at: string
  updated_at: string
}

export function fetchLogFilterPresets(logType: string): Promise<LogFilterPreset[]> {
  return apiGet<LogFilterPreset[]>(`/api/v1/log-filter-presets?log_type=${encodeURIComponent(logType)}`)
}

export function createLogFilterPreset(
  name: string,
  logType: string,
  filter: LogFilter,
): Promise<LogFilterPreset> {
  return apiPost<LogFilterPreset>('/api/v1/log-filter-presets', {
    name,
    log_type: logType,
    filter,
  })
}

export function deleteLogFilterPreset(id: string): Promise<void> {
  return apiDelete(`/api/v1/log-filter-presets/${id}`)
}

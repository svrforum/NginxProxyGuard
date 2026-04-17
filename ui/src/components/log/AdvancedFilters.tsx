import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import DatePicker from 'react-datepicker';
import { ko } from 'date-fns/locale';
import {
  fetchDistinctHosts, fetchDistinctIPs, fetchDistinctUserAgents,
  fetchDistinctCountries, fetchDistinctURIs, fetchDistinctMethods
} from '../../api/logs';
import type { LogFilter, CountryStat } from '../../types/log';
import { getDefaultDateRange } from './LogUtils';
import { AutocompleteInput } from './BasicFilters';

// Advanced Filter Panel Component
interface AdvancedFilterPanelProps {
  filter: LogFilter;
  onFilterChange: (filter: LogFilter) => void;
  logType?: 'access' | 'error' | 'modsec';
  onClose: () => void;
}

export function AdvancedFilterPanel({ filter, onFilterChange, logType, onClose }: AdvancedFilterPanelProps) {
  const [localFilter, setLocalFilter] = useState<LogFilter>(filter);
  const [showExcludeFilters, setShowExcludeFilters] = useState(
    !!(filter.exclude_ips?.length || filter.exclude_user_agents?.length ||
       filter.exclude_uris?.length || filter.exclude_hosts?.length || filter.exclude_countries?.length)
  );

  const countriesQuery = useQuery({
    queryKey: ['log-countries'],
    queryFn: fetchDistinctCountries,
    staleTime: 60000,
  });

  const methodsQuery = useQuery({
    queryKey: ['log-methods'],
    queryFn: fetchDistinctMethods,
    staleTime: 60000,
  });

  const handleApply = () => {
    onFilterChange(localFilter);
    onClose();
  };

  const handleReset = () => {
    const defaultDates = getDefaultDateRange();
    const resetFilter: LogFilter = {
      log_type: filter.log_type,
      ...defaultDates,
    };
    setLocalFilter(resetFilter);
    onFilterChange(resetFilter);
    onClose();
  };

  const updateFilter = (key: keyof LogFilter, value: unknown) => {
    setLocalFilter(prev => ({
      ...prev,
      [key]: value === '' ? undefined : value,
    }));
  };

  // Status code options
  const statusCodeGroups = [
    { label: '2xx Success', codes: [200, 201, 204] },
    { label: '3xx Redirect', codes: [301, 302, 304] },
    { label: '4xx Client Error', codes: [400, 401, 403, 404, 429] },
    { label: '5xx Server Error', codes: [500, 502, 503, 504] },
  ];

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700 p-4 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Advanced Filters</h3>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-400">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Date Range */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Start Date</label>
          <DatePicker
            selected={localFilter.start_time ? new Date(localFilter.start_time) : null}
            onChange={(date: Date | null) => updateFilter('start_time', date ? date.toISOString() : undefined)}
            showTimeSelect
            timeFormat="HH:mm"
            timeIntervals={15}
            dateFormat="yyyy-MM-dd HH:mm"
            locale={ko}
            placeholderText="시작 날짜 선택"
            isClearable
            maxDate={localFilter.end_time ? new Date(localFilter.end_time) : undefined}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">End Date</label>
          <DatePicker
            selected={localFilter.end_time ? new Date(localFilter.end_time) : null}
            onChange={(date: Date | null) => updateFilter('end_time', date ? date.toISOString() : undefined)}
            showTimeSelect
            timeFormat="HH:mm"
            timeIntervals={15}
            dateFormat="yyyy-MM-dd HH:mm"
            locale={ko}
            placeholderText="종료 날짜 선택"
            isClearable
            minDate={localFilter.start_time ? new Date(localFilter.start_time) : undefined}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>

        {/* Host with Autocomplete */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Host</label>
          <AutocompleteInput
            value={localFilter.host || ''}
            onChange={(v) => updateFilter('host', v)}
            placeholder="Filter by host..."
            fetchSuggestions={fetchDistinctHosts}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>

        {/* Client IP with Autocomplete */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Client IP</label>
          <AutocompleteInput
            value={localFilter.client_ip || ''}
            onChange={(v) => updateFilter('client_ip', v)}
            placeholder="Filter by IP..."
            fetchSuggestions={fetchDistinctIPs}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>

        {/* URI with Autocomplete */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">URI</label>
          <AutocompleteInput
            value={localFilter.uri || ''}
            onChange={(v) => updateFilter('uri', v)}
            placeholder="Filter by URI..."
            fetchSuggestions={fetchDistinctURIs}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>

        {/* User Agent with Autocomplete */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">User Agent</label>
          <AutocompleteInput
            value={localFilter.user_agent || ''}
            onChange={(v) => updateFilter('user_agent', v)}
            placeholder="Filter by User-Agent..."
            fetchSuggestions={fetchDistinctUserAgents}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>

        {/* HTTP Method */}
        {logType === 'access' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">HTTP Method</label>
            <select
              value={localFilter.method || ''}
              onChange={(e) => updateFilter('method', e.target.value)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value="">All Methods</option>
              {methodsQuery.data?.map(method => (
                <option key={method} value={method}>{method}</option>
              ))}
            </select>
          </div>
        )}

        {/* GeoIP Country */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Country</label>
          <select
            value={localFilter.geo_country_code || ''}
            onChange={(e) => updateFilter('geo_country_code', e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="">All Countries</option>
            {countriesQuery.data?.map((c: CountryStat) => (
              <option key={c.country_code} value={c.country_code}>
                {c.country_code} - {c.country} ({c.count.toLocaleString()})
              </option>
            ))}
          </select>
        </div>

        {/* Status Codes (Multiple Select) */}
        {logType === 'access' && (
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Status Codes</label>
            <div className="flex flex-wrap gap-2">
              {statusCodeGroups.map(group => (
                <div key={group.label} className="flex items-center gap-1">
                  <span className="text-xs text-slate-500 dark:text-slate-400">{group.label}:</span>
                  {group.codes.map(code => (
                    <button
                      key={code}
                      type="button"
                      onClick={() => {
                        const current = localFilter.status_codes || [];
                        if (current.includes(code)) {
                          updateFilter('status_codes', current.filter(c => c !== code));
                        } else {
                          updateFilter('status_codes', [...current, code]);
                        }
                      }}
                      className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                        (localFilter.status_codes || []).includes(code)
                          ? 'bg-primary-500 text-white'
                          : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
                      }`}
                    >
                      {code}
                    </button>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Size Range */}
        {logType === 'access' && (
          <>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Min Size (bytes)</label>
              <input
                type="number"
                value={localFilter.min_size || ''}
                onChange={(e) => updateFilter('min_size', e.target.value ? parseInt(e.target.value) : undefined)}
                placeholder="0"
                min="0"
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Max Size (bytes)</label>
              <input
                type="number"
                value={localFilter.max_size || ''}
                onChange={(e) => updateFilter('max_size', e.target.value ? parseInt(e.target.value) : undefined)}
                placeholder="No limit"
                min="0"
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              />
            </div>
          </>
        )}

        {/* Min Request Time (Slow Requests) */}
        {logType === 'access' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Min Request Time (sec)</label>
            <input
              type="number"
              step="0.1"
              value={localFilter.min_request_time || ''}
              onChange={(e) => updateFilter('min_request_time', e.target.value ? parseFloat(e.target.value) : undefined)}
              placeholder="0"
              min="0"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
          </div>
        )}

        {/* Block Reason Filter */}
        {logType === 'access' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Block Reason</label>
            <select
              value={localFilter.block_reason || ''}
              onChange={(e) => updateFilter('block_reason', e.target.value || undefined)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value="">All Requests</option>
              <option value="none">Not Blocked</option>
              <option value="waf">WAF</option>
              <option value="bot_filter">Bot Filter</option>
              <option value="rate_limit">Rate Limit</option>
              <option value="geo_block">Geo Block</option>
              <option value="banned_ip">Banned IP</option>
            </select>
          </div>
        )}

        {/* Bot Category Filter */}
        {logType === 'access' && localFilter.block_reason === 'bot_filter' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Bot Category</label>
            <select
              value={localFilter.bot_category || ''}
              onChange={(e) => updateFilter('bot_category', e.target.value || undefined)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value="">All Bots</option>
              <option value="bad_bot">Bad Bot</option>
              <option value="ai_bot">AI Bot</option>
              <option value="suspicious">Suspicious</option>
              <option value="search_engine">Search Engine</option>
            </select>
          </div>
        )}

        {/* Sort Options */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Sort By</label>
          <select
            value={localFilter.sort_by || 'timestamp'}
            onChange={(e) => updateFilter('sort_by', e.target.value as LogFilter['sort_by'])}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="timestamp">Time</option>
            <option value="body_bytes_sent">Size</option>
            <option value="request_time">Request Time</option>
            <option value="status_code">Status Code</option>
            <option value="client_ip">Client IP</option>
            <option value="host">Host</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Sort Order</label>
          <select
            value={localFilter.sort_order || 'desc'}
            onChange={(e) => updateFilter('sort_order', e.target.value as 'asc' | 'desc')}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          >
            <option value="desc">Descending</option>
            <option value="asc">Ascending</option>
          </select>
        </div>
      </div>

      {/* Exclude Filters Section */}
      <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
        <button
          type="button"
          onClick={() => setShowExcludeFilters(!showExcludeFilters)}
          className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
        >
          <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
          Exclude Filters
          <svg className={`w-4 h-4 transition-transform ${showExcludeFilters ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
          {(localFilter.exclude_ips?.length || localFilter.exclude_user_agents?.length ||
            localFilter.exclude_uris?.length || localFilter.exclude_hosts?.length || localFilter.exclude_countries?.length) && (
            <span className="px-1.5 py-0.5 bg-red-500 text-white rounded-full text-xs">
              {(localFilter.exclude_ips?.length ? 1 : 0) + (localFilter.exclude_user_agents?.length ? 1 : 0) +
               (localFilter.exclude_uris?.length ? 1 : 0) + (localFilter.exclude_hosts?.length ? 1 : 0) +
               (localFilter.exclude_countries?.length ? 1 : 0)}
            </span>
          )}
        </button>
        {showExcludeFilters && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-3">
          {/* Exclude IPs */}
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Exclude IPs</label>
            <input
              type="text"
              value={(localFilter.exclude_ips || []).join(', ')}
              onChange={(e) => {
                const values = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                updateFilter('exclude_ips', values.length > 0 ? values : undefined);
              }}
              placeholder="192.168.1.1, 10.0.0.1"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Comma separated</p>
          </div>

          {/* Exclude User Agents */}
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Exclude User Agents</label>
            <input
              type="text"
              value={(localFilter.exclude_user_agents || []).join(', ')}
              onChange={(e) => {
                const values = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                updateFilter('exclude_user_agents', values.length > 0 ? values : undefined);
              }}
              placeholder="bot, crawler, spider"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Contains match, comma separated</p>
          </div>

          {/* Exclude URIs */}
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Exclude URIs</label>
            <input
              type="text"
              value={(localFilter.exclude_uris || []).join(', ')}
              onChange={(e) => {
                const values = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                updateFilter('exclude_uris', values.length > 0 ? values : undefined);
              }}
              placeholder="/health, /metrics"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Contains match, comma separated</p>
          </div>

          {/* Exclude Hosts */}
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Exclude Hosts</label>
            <input
              type="text"
              value={(localFilter.exclude_hosts || []).join(', ')}
              onChange={(e) => {
                const values = e.target.value.split(',').map(s => s.trim()).filter(Boolean);
                updateFilter('exclude_hosts', values.length > 0 ? values : undefined);
              }}
              placeholder="internal.example.com"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Comma separated</p>
          </div>

          {/* Exclude Countries */}
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">Exclude Countries</label>
            <input
              type="text"
              value={(localFilter.exclude_countries || []).join(', ')}
              onChange={(e) => {
                const values = e.target.value.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
                updateFilter('exclude_countries', values.length > 0 ? values : undefined);
              }}
              placeholder="US, CN, RU"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Country codes, comma separated</p>
          </div>
        </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
        <button
          onClick={handleReset}
          className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
        >
          Reset
        </button>
        <button
          onClick={handleApply}
          className="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors"
        >
          Apply Filters
        </button>
      </div>
    </div>
  );
}

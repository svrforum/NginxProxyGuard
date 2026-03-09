import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import DatePicker from 'react-datepicker';
import { ko } from 'date-fns/locale';
import {
  fetchDistinctHosts, fetchDistinctIPs, fetchDistinctUserAgents,
  fetchDistinctCountries, fetchDistinctURIs, fetchDistinctMethods
} from '../../api/logs';
import type { LogFilter, CountryStat } from '../../types/log';
import { getDefaultDateRange, formatBytes } from './LogUtils';

// Autocomplete Input Component
interface AutocompleteInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  fetchSuggestions: (search: string) => Promise<string[]>;
  className?: string;
}

export function AutocompleteInput({ value, onChange, placeholder, fetchSuggestions, className }: AutocompleteInputProps) {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    onChange(newValue);

    if (newValue.length >= 1) {
      setLoading(true);
      try {
        const results = await fetchSuggestions(newValue);
        setSuggestions(results || []);
        setShowSuggestions(true);
      } catch {
        setSuggestions([]);
      } finally {
        setLoading(false);
      }
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
  };

  const handleSelect = (suggestion: string) => {
    onChange(suggestion);
    setShowSuggestions(false);
  };

  return (
    <div className="relative">
      <input
        type="text"
        value={value}
        onChange={handleInputChange}
        onFocus={() => suggestions.length > 0 && setShowSuggestions(true)}
        onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
        placeholder={placeholder}
        className={className}
      />
      {loading && (
        <div className="absolute right-2 top-1/2 -translate-y-1/2">
          <div className="w-4 h-4 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
        </div>
      )}
      {showSuggestions && suggestions.length > 0 && (
        <ul className="absolute z-50 w-full mt-1 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg max-h-48 overflow-y-auto">
          {suggestions.map((suggestion, index) => (
            <li
              key={index}
              onClick={() => handleSelect(suggestion)}
              className="px-3 py-2 text-sm cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-700 truncate"
            >
              {suggestion}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

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

// Active Filter Tags Component
interface ActiveFilterTagsProps {
  filter: LogFilter;
  onRemove: (key: keyof LogFilter) => void;
}

export function ActiveFilterTags({ filter, onRemove }: ActiveFilterTagsProps) {
  const tags: { key: keyof LogFilter; label: string; value: string; isExclude?: boolean }[] = [];

  if (filter.start_time) tags.push({ key: 'start_time', label: 'From', value: new Date(filter.start_time).toLocaleString() });
  if (filter.end_time) tags.push({ key: 'end_time', label: 'To', value: new Date(filter.end_time).toLocaleString() });
  if (filter.host) tags.push({ key: 'host', label: 'Host', value: filter.host });
  if (filter.client_ip) tags.push({ key: 'client_ip', label: 'IP', value: filter.client_ip });
  if (filter.uri) tags.push({ key: 'uri', label: 'URI', value: filter.uri });
  if (filter.user_agent) tags.push({ key: 'user_agent', label: 'UA', value: filter.user_agent.slice(0, 30) + '...' });
  if (filter.method) tags.push({ key: 'method', label: 'Method', value: filter.method });
  if (filter.geo_country_code) tags.push({ key: 'geo_country_code', label: 'Country', value: filter.geo_country_code });
  if (filter.status_codes?.length) tags.push({ key: 'status_codes', label: 'Status', value: filter.status_codes.join(', ') });
  if (filter.min_size) tags.push({ key: 'min_size', label: 'Min Size', value: formatBytes(filter.min_size) });
  if (filter.max_size) tags.push({ key: 'max_size', label: 'Max Size', value: formatBytes(filter.max_size) });
  if (filter.min_request_time) tags.push({ key: 'min_request_time', label: 'Slow', value: `>${filter.min_request_time}s` });
  if (filter.block_reason) {
    const blockReasonLabels: Record<string, string> = {
      'none': 'Not Blocked',
      'waf': 'WAF',
      'bot_filter': 'Bot Filter',
      'rate_limit': 'Rate Limit',
      'geo_block': 'Geo Block',
      'banned_ip': 'Banned IP',
    };
    tags.push({ key: 'block_reason', label: 'Block', value: blockReasonLabels[filter.block_reason] || filter.block_reason });
  }
  if (filter.bot_category) {
    const botCategoryLabels: Record<string, string> = {
      'bad_bot': 'Bad Bot',
      'ai_bot': 'AI Bot',
      'suspicious': 'Suspicious',
      'search_engine': 'Search Engine',
    };
    tags.push({ key: 'bot_category', label: 'Bot', value: botCategoryLabels[filter.bot_category] || filter.bot_category });
  }
  if (filter.sort_by && filter.sort_by !== 'timestamp') tags.push({ key: 'sort_by', label: 'Sort', value: filter.sort_by });

  // Exclude filters (shown with red styling)
  if (filter.exclude_ips?.length) tags.push({ key: 'exclude_ips', label: 'Exclude IPs', value: filter.exclude_ips.join(', '), isExclude: true });
  if (filter.exclude_user_agents?.length) tags.push({ key: 'exclude_user_agents', label: 'Exclude UA', value: filter.exclude_user_agents.join(', '), isExclude: true });
  if (filter.exclude_uris?.length) tags.push({ key: 'exclude_uris', label: 'Exclude URIs', value: filter.exclude_uris.join(', '), isExclude: true });
  if (filter.exclude_hosts?.length) tags.push({ key: 'exclude_hosts', label: 'Exclude Hosts', value: filter.exclude_hosts.join(', '), isExclude: true });
  if (filter.exclude_countries?.length) tags.push({ key: 'exclude_countries', label: 'Exclude Countries', value: filter.exclude_countries.join(', '), isExclude: true });

  if (tags.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-2 mb-4">
      {tags.map(tag => (
        <span
          key={tag.key}
          className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs ${
            tag.isExclude
              ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400'
              : 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-400'
          }`}
        >
          <span className="font-medium">{tag.label}:</span>
          <span className="max-w-[150px] truncate" title={tag.value}>{tag.value}</span>
          <button
            onClick={() => onRemove(tag.key)}
            className={`ml-1 ${tag.isExclude ? 'hover:text-red-900' : 'hover:text-primary-900'}`}
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </span>
      ))}
    </div>
  );
}

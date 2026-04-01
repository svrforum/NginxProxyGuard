import { useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import DatePicker from 'react-datepicker';
import { ko } from 'date-fns/locale';
import { HelpTip } from '../common/HelpTip';
import {
  fetchDistinctHosts, fetchDistinctIPs, fetchDistinctUserAgents,
  fetchDistinctCountries, fetchDistinctURIs, fetchDistinctMethods
} from '../../api/logs';
import type { LogFilter, CountryStat } from '../../types/log';
import { TagInput } from './filters';
import { getDefaultDateRange } from './utils';

interface AdvancedFilterPanelProps {
  filter: LogFilter;
  onFilterChange: (filter: LogFilter) => void;
  logType?: 'access' | 'error' | 'modsec';
  onClose: () => void;
}

export function AdvancedFilterPanel({ filter, onFilterChange, logType, onClose }: AdvancedFilterPanelProps) {
  const { t, i18n } = useTranslation('logs');
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

  // Wrapper function to convert CountryStat[] to string[] for TagInput
  const fetchCountryCodes = useCallback(async (search: string): Promise<string[]> => {
    const countries = countriesQuery.data || [];
    const searchLower = search.toLowerCase();
    return countries
      .filter(c => c.country_code.toLowerCase().includes(searchLower) ||
                   (c.country && c.country.toLowerCase().includes(searchLower)))
      .map(c => c.country_code)
      .slice(0, 20);
  }, [countriesQuery.data]);

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
    { label: t('charts.statusGroups.success'), codes: [200, 201, 204] },
    { label: t('charts.statusGroups.redirect'), codes: [301, 302, 304] },
    { label: t('charts.statusGroups.clientError'), codes: [400, 401, 403, 404, 429] },
    { label: t('charts.statusGroups.serverError'), codes: [500, 502, 503, 504] },
  ];

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700 p-4 mb-4 transition-colors">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{t('viewer.advancedFilters')}</h3>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Date Range */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.startDate')}
            <HelpTip content={t('filters.startDateHelp')} />
          </label>
          <DatePicker
            selected={localFilter.start_time ? new Date(localFilter.start_time) : null}
            onChange={(date: Date | null) => updateFilter('start_time', date ? date.toISOString() : undefined)}
            showTimeSelect
            timeFormat="HH:mm"
            timeIntervals={15}
            dateFormat="yyyy-MM-dd HH:mm"
            locale={i18n.language === 'ko' ? ko : undefined}
            placeholderText={t('filters.startDate')}
            isClearable
            maxDate={localFilter.end_time ? new Date(localFilter.end_time) : undefined}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.endDate')}
            <HelpTip content={t('filters.endDateHelp')} />
          </label>
          <DatePicker
            selected={localFilter.end_time ? new Date(localFilter.end_time) : null}
            onChange={(date: Date | null) => updateFilter('end_time', date ? date.toISOString() : undefined)}
            showTimeSelect
            timeFormat="HH:mm"
            timeIntervals={15}
            dateFormat="yyyy-MM-dd HH:mm"
            locale={i18n.language === 'ko' ? ko : undefined}
            placeholderText={t('filters.endDate')}
            isClearable
            minDate={localFilter.start_time ? new Date(localFilter.start_time) : undefined}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
          />
        </div>

        {/* Host with Multi-select */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.host')}
            <HelpTip content={t('filters.hostHelp')} />
          </label>
          <TagInput
            values={localFilter.hosts || []}
            onChange={(values) => updateFilter('hosts', values.length > 0 ? values : undefined)}
            placeholder={t('filters.hostPlaceholder')}
            fetchSuggestions={fetchDistinctHosts}
            className="border-slate-300"
            helpText={t('filters.tagInputHelp')}
          />
        </div>

        {/* Client IP with Multi-select */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.clientIp')}
            <HelpTip content={t('filters.clientIpHelp')} />
          </label>
          <TagInput
            values={localFilter.client_ips || []}
            onChange={(values) => updateFilter('client_ips', values.length > 0 ? values : undefined)}
            placeholder={t('filters.ipPlaceholder')}
            fetchSuggestions={fetchDistinctIPs}
            className="border-slate-300"
            helpText={t('filters.tagInputHelp')}
          />
        </div>

        {/* URI with Multi-select */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.uri')}
            <HelpTip content={t('filters.uriHelp')} />
          </label>
          <TagInput
            values={localFilter.uris || []}
            onChange={(values) => updateFilter('uris', values.length > 0 ? values : undefined)}
            placeholder={t('filters.uriPlaceholder')}
            fetchSuggestions={fetchDistinctURIs}
            className="border-slate-300"
            helpText={t('filters.tagInputHelp')}
          />
        </div>

        {/* User Agent with Multi-select */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.userAgent')}
            <HelpTip content={t('filters.userAgentHelp')} />
          </label>
          <TagInput
            values={localFilter.user_agents || []}
            onChange={(values) => updateFilter('user_agents', values.length > 0 ? values : undefined)}
            placeholder={t('filters.userAgentPlaceholder')}
            fetchSuggestions={fetchDistinctUserAgents}
            className="border-slate-300"
            helpText={t('filters.tagInputHelp')}
          />
        </div>

        {/* HTTP Method */}
        {logType === 'access' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('filters.method')}
              <HelpTip content={t('filters.methodHelp')} />
            </label>
            <select
              value={localFilter.method || ''}
              onChange={(e) => updateFilter('method', e.target.value)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="">{t('filters.allMethods')}</option>
              {methodsQuery.data?.map(method => (
                <option key={method} value={method}>{method}</option>
              ))}
            </select>
          </div>
        )}

        {/* GeoIP Country */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.country')}
            <HelpTip content={t('filters.countryHelp')} />
          </label>
          <select
            value={localFilter.geo_country_code || ''}
            onChange={(e) => updateFilter('geo_country_code', e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="">{t('filters.allCountries')}</option>
            {countriesQuery.data?.map((c: CountryStat) => (
              <option key={c.country_code} value={c.country_code}>
                {c.country_code} - {c.country} ({c.count.toLocaleString()})
              </option>
            ))}
          </select>
        </div>

        {/* Rule ID Filter (for modsec logs only) */}
        {logType === 'modsec' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('filters.ruleId')}
              <HelpTip content={t('filters.ruleIdHelp')} />
            </label>
            <input
              type="text"
              value={localFilter.rule_id || ''}
              onChange={(e) => {
                const value = e.target.value;
                // Only allow numeric input
                if (value === '' || /^\d+$/.test(value)) {
                  updateFilter('rule_id', value ? parseInt(value) : undefined);
                }
              }}
              placeholder={t('filters.ruleIdPlaceholder')}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
            />
          </div>
        )}

        {/* Status Codes (Multiple Select) */}
        {logType === 'access' && (
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('filters.statusCodes')}
              <HelpTip content={t('filters.statusCodesHelp')} />
            </label>
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
                      className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${(localFilter.status_codes || []).includes(code)
                        ? 'bg-primary-500 text-white'
                        : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600'
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
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.minSize')}
                <HelpTip content={t('filters.minSizeHelp')} />
              </label>
              <input
                type="number"
                value={localFilter.min_size || ''}
                onChange={(e) => updateFilter('min_size', e.target.value ? parseInt(e.target.value) : undefined)}
                placeholder="0"
                min="0"
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.maxSize')}
                <HelpTip content={t('filters.maxSizeHelp')} />
              </label>
              <input
                type="number"
                value={localFilter.max_size || ''}
                onChange={(e) => updateFilter('max_size', e.target.value ? parseInt(e.target.value) : undefined)}
                placeholder={t('filters.noLimit')}
                min="0"
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
              />
            </div>
          </>
        )}

        {/* Min Request Time (Slow Requests) */}
        {logType === 'access' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('filters.minRequestTime')}
              <HelpTip content={t('filters.requestTimeHelp')} />
            </label>
            <input
              type="number"
              step="0.1"
              value={localFilter.min_request_time || ''}
              onChange={(e) => updateFilter('min_request_time', e.target.value ? parseFloat(e.target.value) : undefined)}
              placeholder="0"
              min="0"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            />
          </div>
        )}

        {/* Block Reason Filter */}
        {logType === 'access' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('filters.blockReason')}
              <HelpTip content={t('filters.blockReasonHelp')} />
            </label>
            <select
              value={localFilter.block_reason || ''}
              onChange={(e) => updateFilter('block_reason', e.target.value || undefined)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="">{t('filters.allRequests')}</option>
              <option value="none">{t('reasons.none')}</option>
              <option value="waf">{t('reasons.waf')}</option>
              <option value="bot_filter">{t('reasons.botFilter')}</option>
              <option value="rate_limit">{t('reasons.rateLimit')}</option>
              <option value="geo_block">{t('reasons.geoBlock')}</option>
              <option value="banned_ip">{t('reasons.bannedIp')}</option>
              <option value="filter_subscription">{t('reasons.filterSubscription')}</option>
            </select>
          </div>
        )}

        {/* Bot Category Filter */}
        {logType === 'access' && localFilter.block_reason === 'bot_filter' && (
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
              {t('filters.botCategory')}
              <HelpTip content={t('filters.botCategoryHelp')} />
            </label>
            <select
              value={localFilter.bot_category || ''}
              onChange={(e) => updateFilter('bot_category', e.target.value || undefined)}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="">{t('filters.allBots')}</option>
              <option value="bad_bot">{t('bots.badBot')}</option>
              <option value="ai_bot">{t('bots.aiBot')}</option>
              <option value="suspicious">{t('bots.suspicious')}</option>
              <option value="search_engine">{t('bots.searchEngine')}</option>
            </select>
          </div>
        )}

        {/* Sort Options */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
            {t('filters.sortBy')}
            <HelpTip content={t('filters.sortByHelp')} />
          </label>
          <select
            value={localFilter.sort_by || 'timestamp'}
            onChange={(e) => updateFilter('sort_by', e.target.value as LogFilter['sort_by'])}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="timestamp">{t('sort.time')}</option>
            <option value="body_bytes_sent">{t('sort.size')}</option>
            <option value="request_time">{t('sort.requestTime')}</option>
            <option value="status_code">{t('sort.statusCode')}</option>
            <option value="client_ip">{t('sort.clientIp')}</option>
            <option value="host">{t('sort.host')}</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1 flex items-center gap-1">
            {t('filters.sortOrder')}
            <HelpTip content={t('filters.sortOrderHelp')} />
          </label>
          <select
            value={localFilter.sort_order || 'desc'}
            onChange={(e) => updateFilter('sort_order', e.target.value as 'asc' | 'desc')}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="desc">{t('sort.desc')}</option>
            <option value="asc">{t('sort.asc')}</option>
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
          {t('filters.excludeFilters')}
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
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.excludeIps')}
                <HelpTip content={t('filters.excludeIpsHelp')} />
              </label>
              <TagInput
                values={localFilter.exclude_ips || []}
                onChange={(values) => updateFilter('exclude_ips', values.length > 0 ? values : undefined)}
                placeholder={t('filters.placeholders.ipExample')}
                fetchSuggestions={fetchDistinctIPs}
                className="border-slate-300"
                helpText={t('filters.tagInputHelp')}
              />
            </div>

            {/* Exclude User Agents */}
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.excludeUserAgents')}
                <HelpTip content={t('filters.excludeUserAgentsHelp')} />
              </label>
              <TagInput
                values={localFilter.exclude_user_agents || []}
                onChange={(values) => updateFilter('exclude_user_agents', values.length > 0 ? values : undefined)}
                placeholder={t('filters.placeholders.userAgentExample')}
                fetchSuggestions={fetchDistinctUserAgents}
                className="border-slate-300"
                helpText={t('filters.containsMatch')}
              />
            </div>

            {/* Exclude URIs */}
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.excludeUris')}
                <HelpTip content={t('filters.excludeUrisHelp')} />
              </label>
              <TagInput
                values={localFilter.exclude_uris || []}
                onChange={(values) => updateFilter('exclude_uris', values.length > 0 ? values : undefined)}
                placeholder={t('filters.placeholders.uriExample')}
                fetchSuggestions={fetchDistinctURIs}
                className="border-slate-300"
                helpText={t('filters.containsMatch')}
              />
            </div>

            {/* Exclude Hosts */}
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.excludeHosts')}
                <HelpTip content={t('filters.excludeHostsHelp')} />
              </label>
              <TagInput
                values={localFilter.exclude_hosts || []}
                onChange={(values) => updateFilter('exclude_hosts', values.length > 0 ? values : undefined)}
                placeholder={t('filters.placeholders.hostExample')}
                fetchSuggestions={fetchDistinctHosts}
                className="border-slate-300"
                helpText={t('filters.tagInputHelp')}
              />
            </div>

            {/* Exclude Countries */}
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                {t('filters.excludeCountries')}
                <HelpTip content={t('filters.excludeCountriesHelp')} />
              </label>
              <TagInput
                values={localFilter.exclude_countries || []}
                onChange={(values) => updateFilter('exclude_countries', values.length > 0 ? values.map(v => v.toUpperCase()) : undefined)}
                placeholder={t('filters.placeholders.countryCodeExample')}
                fetchSuggestions={fetchCountryCodes}
                className="border-slate-300"
                helpText={t('filters.countryCodes')}
              />
            </div>
          </div>
        )}
      </div>

      {/* Action Buttons */}
      <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
        <button
          onClick={handleReset}
          className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
        >
          {t('filters.reset')}
        </button>
        <button
          onClick={handleApply}
          className="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors"
        >
          {t('filters.apply')}
        </button>
      </div>
    </div>
  );
}

import { useTranslation } from 'react-i18next';
import type { LogFilter } from '../../types/log';
import { formatBytes } from './utils';

interface ActiveFilterTagsProps {
  filter: LogFilter;
  onRemove: (key: keyof LogFilter) => void;
}

export function ActiveFilterTags({ filter, onRemove }: ActiveFilterTagsProps) {
  const { t, i18n } = useTranslation('logs');
  const tags: { key: keyof LogFilter; label: string; value: string; isExclude?: boolean }[] = [];

  if (filter.start_time) tags.push({ key: 'start_time', label: t('filters.startDate'), value: new Date(filter.start_time).toLocaleString(i18n.language) });
  if (filter.end_time) tags.push({ key: 'end_time', label: t('filters.endDate'), value: new Date(filter.end_time).toLocaleString(i18n.language) });
  // Array filters (new multi-select)
  if (filter.hosts?.length) tags.push({ key: 'hosts', label: t('filters.host'), value: filter.hosts.join(', ') });
  if (filter.client_ips?.length) tags.push({ key: 'client_ips', label: t('filters.clientIp'), value: filter.client_ips.join(', ') });
  if (filter.uris?.length) tags.push({ key: 'uris', label: t('filters.uri'), value: filter.uris.join(', ') });
  if (filter.user_agents?.length) tags.push({ key: 'user_agents', label: 'UA', value: filter.user_agents.join(', ').slice(0, 50) + (filter.user_agents.join(', ').length > 50 ? '...' : '') });
  // Legacy single-value filters
  if (filter.host) tags.push({ key: 'host', label: t('filters.host'), value: filter.host });
  if (filter.client_ip) tags.push({ key: 'client_ip', label: t('filters.clientIp'), value: filter.client_ip });
  if (filter.uri) tags.push({ key: 'uri', label: t('filters.uri'), value: filter.uri });
  if (filter.user_agent) tags.push({ key: 'user_agent', label: 'UA', value: filter.user_agent.slice(0, 30) + '...' });
  if (filter.method) tags.push({ key: 'method', label: t('filters.method'), value: filter.method });
  if (filter.geo_country_code) tags.push({ key: 'geo_country_code', label: t('filters.country'), value: filter.geo_country_code });
  if (filter.status_codes?.length) tags.push({ key: 'status_codes', label: t('filters.statusCodes'), value: filter.status_codes.join(', ') });
  if (filter.min_size) tags.push({ key: 'min_size', label: t('filters.minSize'), value: formatBytes(filter.min_size) });
  if (filter.max_size) tags.push({ key: 'max_size', label: t('filters.maxSize'), value: formatBytes(filter.max_size) });
  if (filter.min_request_time) tags.push({ key: 'min_request_time', label: t('filters.minRequestTime'), value: `>${filter.min_request_time}s` });
  if (filter.block_reason) {
    const blockReasonLabels: Record<string, string> = {
      'none': t('reasons.none'),
      'waf': t('reasons.waf'),
      'bot_filter': t('reasons.botFilter'),
      'rate_limit': t('reasons.rateLimit'),
      'geo_block': t('reasons.geoBlock'),
      'banned_ip': t('reasons.bannedIp'),
      'exploit_block': t('reasons.exploitBlock'),
      'filter_subscription': t('reasons.filterSubscription'),
    };
    tags.push({ key: 'block_reason', label: t('filters.blockReason'), value: blockReasonLabels[filter.block_reason] || filter.block_reason });
  }
  if (filter.bot_category) {
    const botCategoryLabels: Record<string, string> = {
      'bad_bot': t('bots.badBot'),
      'ai_bot': t('bots.aiBot'),
      'suspicious': t('bots.suspicious'),
      'search_engine': t('bots.searchEngine'),
    };
    tags.push({ key: 'bot_category', label: t('filters.botCategory'), value: botCategoryLabels[filter.bot_category] || filter.bot_category });
  }
  if (filter.sort_by && filter.sort_by !== 'timestamp') tags.push({ key: 'sort_by', label: t('filters.sortBy'), value: filter.sort_by });

  // Exclude filters (shown with red styling)
  if (filter.exclude_ips?.length) tags.push({ key: 'exclude_ips', label: t('filters.excludeIps'), value: filter.exclude_ips.join(', '), isExclude: true });
  if (filter.exclude_user_agents?.length) tags.push({ key: 'exclude_user_agents', label: t('filters.excludeUserAgents'), value: filter.exclude_user_agents.join(', '), isExclude: true });
  if (filter.exclude_uris?.length) tags.push({ key: 'exclude_uris', label: t('filters.excludeUris'), value: filter.exclude_uris.join(', '), isExclude: true });
  if (filter.exclude_hosts?.length) tags.push({ key: 'exclude_hosts', label: t('filters.excludeHosts'), value: filter.exclude_hosts.join(', '), isExclude: true });
  if (filter.exclude_countries?.length) tags.push({ key: 'exclude_countries', label: t('filters.excludeCountries'), value: filter.exclude_countries.join(', '), isExclude: true });

  if (tags.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-2 mb-4">
      {tags.map(tag => (
        <span
          key={tag.key}
          className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs ${tag.isExclude
            ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300'
            : 'bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
            }`}
        >
          <span className="font-medium">{tag.label}:</span>
          <span className="max-w-[150px] truncate" title={tag.value}>{tag.value}</span>
          <button
            onClick={() => onRemove(tag.key)}
            className={`ml-1 ${tag.isExclude ? 'hover:text-red-900 dark:hover:text-red-200' : 'hover:text-primary-900 dark:hover:text-primary-200'}`}
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

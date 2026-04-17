import type { LogFilter } from '../../types/log';
import { formatBytes } from './LogUtils';

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

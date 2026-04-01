import type { Log, LogType, BlockReason, BotCategory } from '../../types/log';

export function StatusCodeBadge({ code }: { code: number }) {
  let color = 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200';
  if (code >= 200 && code < 300) color = 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
  else if (code >= 300 && code < 400) color = 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
  else if (code >= 400 && code < 500) color = 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
  else if (code >= 500) color = 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
  else if (code === 101) color = 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300';

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {code}
    </span>
  );
}

export function LogTypeBadge({ type }: { type: LogType }) {
  const colors: Record<LogType, string> = {
    access: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
    error: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
    modsec: 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[type]}`}>
      {type}
    </span>
  );
}

export function BlockReasonBadge({ reason, category }: { reason?: BlockReason; category?: BotCategory }) {
  if (!reason || reason === 'none') return null;

  const config: Record<string, { bg: string; text: string; label: string }> = {
    waf: { bg: 'bg-orange-100 dark:bg-orange-900/30', text: 'text-orange-800 dark:text-orange-300', label: 'WAF' },
    bot_filter: { bg: 'bg-purple-100 dark:bg-purple-900/30', text: 'text-purple-800 dark:text-purple-300', label: 'Bot' },
    rate_limit: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-800 dark:text-yellow-300', label: 'Rate' },
    geo_block: { bg: 'bg-blue-100 dark:bg-blue-900/30', text: 'text-blue-800 dark:text-blue-300', label: 'Geo' },
    banned_ip: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-800 dark:text-red-300', label: 'Ban' },
    exploit_block: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-800 dark:text-red-300', label: 'Exploit' },
    uri_block: { bg: 'bg-pink-100 dark:bg-pink-900/30', text: 'text-pink-800 dark:text-pink-300', label: 'URI' },
    cloud_provider_challenge: { bg: 'bg-cyan-100 dark:bg-cyan-900/30', text: 'text-cyan-800 dark:text-cyan-300', label: 'Cloud' },
    cloud_provider_block: { bg: 'bg-cyan-100 dark:bg-cyan-900/30', text: 'text-cyan-800 dark:text-cyan-300', label: 'Cloud' },
    access_denied: { bg: 'bg-rose-100 dark:bg-rose-900/30', text: 'text-rose-800 dark:text-rose-300', label: 'Denied' },
    filter_subscription: { bg: 'bg-teal-100 dark:bg-teal-900/30', text: 'text-teal-800 dark:text-teal-300', label: 'Filter' },
  };

  const cfg = config[reason] || { bg: 'bg-gray-100 dark:bg-gray-700', text: 'text-gray-800 dark:text-gray-200', label: reason };
  const categoryLabel = category ? ` (${category.replace('_', ' ')})` : '';

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${cfg.bg} ${cfg.text}`} title={`${cfg.label}${categoryLabel}`}>
      {cfg.label}
    </span>
  );
}

export function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300',
    POST: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
    PUT: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
    PATCH: 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300',
    DELETE: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
    HEAD: 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200',
    OPTIONS: 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[method] || 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-200'}`}>
      {method}
    </span>
  );
}

export function GeoIPBadge({ log }: { log: Log }) {
  if (!log.geo_country_code) return <span className="text-xs text-slate-400 dark:text-slate-500">-</span>;

  const flagUrl = `https://flagcdn.com/16x12/${log.geo_country_code.toLowerCase()}.png`;

  return (
    <span className="inline-flex items-center gap-1 text-xs text-slate-600 dark:text-slate-400" title={`${log.geo_country || log.geo_country_code}${log.geo_city ? `, ${log.geo_city}` : ''}${log.geo_org ? ` (${log.geo_org})` : ''}`}>
      <img src={flagUrl} alt={log.geo_country_code} className="w-4 h-3" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
      {log.geo_country_code}
    </span>
  );
}

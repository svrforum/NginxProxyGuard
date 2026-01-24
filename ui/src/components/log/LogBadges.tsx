import type { Log, LogType, BlockReason, BotCategory } from '../../types/log';

export function StatusCodeBadge({ code }: { code: number }) {
  let color = 'bg-gray-100 text-gray-800';
  if (code >= 200 && code < 300) color = 'bg-green-100 text-green-800';
  else if (code >= 300 && code < 400) color = 'bg-blue-100 text-blue-800';
  else if (code >= 400 && code < 500) color = 'bg-yellow-100 text-yellow-800';
  else if (code >= 500) color = 'bg-red-100 text-red-800';
  else if (code === 101) color = 'bg-purple-100 text-purple-800';

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {code}
    </span>
  );
}

export function LogTypeBadge({ type }: { type: LogType }) {
  const colors: Record<LogType, string> = {
    access: 'bg-blue-100 text-blue-800',
    error: 'bg-red-100 text-red-800',
    modsec: 'bg-orange-100 text-orange-800',
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
    waf: { bg: 'bg-orange-100', text: 'text-orange-800', label: 'WAF' },
    bot_filter: { bg: 'bg-purple-100', text: 'text-purple-800', label: 'Bot' },
    rate_limit: { bg: 'bg-yellow-100', text: 'text-yellow-800', label: 'Rate' },
    geo_block: { bg: 'bg-blue-100', text: 'text-blue-800', label: 'Geo' },
    banned_ip: { bg: 'bg-red-100', text: 'text-red-800', label: 'Ban' },
    exploit_block: { bg: 'bg-red-100', text: 'text-red-800', label: 'Exploit' },
    uri_block: { bg: 'bg-pink-100', text: 'text-pink-800', label: 'URI' },
    cloud_provider_challenge: { bg: 'bg-cyan-100', text: 'text-cyan-800', label: 'Cloud' },
    cloud_provider_block: { bg: 'bg-cyan-100', text: 'text-cyan-800', label: 'Cloud' },
    access_denied: { bg: 'bg-rose-100', text: 'text-rose-800', label: 'Denied' },
  };

  const cfg = config[reason] || { bg: 'bg-gray-100', text: 'text-gray-800', label: reason };
  const categoryLabel = category ? ` (${category.replace('_', ' ')})` : '';

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${cfg.bg} ${cfg.text}`} title={`${cfg.label}${categoryLabel}`}>
      {cfg.label}
    </span>
  );
}

export function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET: 'bg-green-100 text-green-800',
    POST: 'bg-blue-100 text-blue-800',
    PUT: 'bg-yellow-100 text-yellow-800',
    PATCH: 'bg-orange-100 text-orange-800',
    DELETE: 'bg-red-100 text-red-800',
    HEAD: 'bg-slate-100 text-slate-800',
    OPTIONS: 'bg-purple-100 text-purple-800',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[method] || 'bg-slate-100 text-slate-800'}`}>
      {method}
    </span>
  );
}

export function GeoIPBadge({ log }: { log: Log }) {
  if (!log.geo_country_code) return <span className="text-xs text-slate-400">-</span>;

  const flagUrl = `https://flagcdn.com/16x12/${log.geo_country_code.toLowerCase()}.png`;

  return (
    <span className="inline-flex items-center gap-1 text-xs text-slate-600" title={`${log.geo_country || log.geo_country_code}${log.geo_city ? `, ${log.geo_city}` : ''}${log.geo_org ? ` (${log.geo_org})` : ''}`}>
      <img src={flagUrl} alt={log.geo_country_code} className="w-4 h-3" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
      {log.geo_country_code}
    </span>
  );
}

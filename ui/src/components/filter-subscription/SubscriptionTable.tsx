import { useTranslation } from 'react-i18next';
import type { FilterSubscription } from '../../types/filter-subscription';

// Well-known community blocklists with detailed info — shared across the
// list and the preset catalog action card.
export const PRESET_LISTS = [
  {
    name: 'Spamhaus DROP',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    type: 'cidr',
    description: 'presets.spamhaus.description',
    detail: 'presets.spamhaus.detail',
    site: 'https://www.spamhaus.org/drop/',
  },
  {
    name: 'FireHOL Level 1',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
    type: 'cidr',
    description: 'presets.firehol.description',
    detail: 'presets.firehol.detail',
    site: 'https://github.com/firehol/blocklist-ipsets',
  },
  {
    name: 'Blocklist.de',
    url: 'https://lists.blocklist.de/lists/all.txt',
    type: 'ip',
    description: 'presets.blocklistde.description',
    detail: 'presets.blocklistde.detail',
    site: 'https://www.blocklist.de/',
  },
  {
    name: 'IPsum Level 3',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
    type: 'ip',
    description: 'presets.ipsum.description',
    detail: 'presets.ipsum.detail',
    site: 'https://github.com/stamparm/ipsum',
  },
  {
    name: 'Emerging Threats',
    url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
    type: 'ip',
    description: 'presets.emergingthreats.description',
    detail: 'presets.emergingthreats.detail',
    site: 'https://rules.emergingthreats.net/',
  },
] as const;

export function getRelativeTime(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return '< 1m';
  if (diffMin < 60) return `${diffMin}m`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d`;
}

export function TypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    ip: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
    cidr: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
    user_agent: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${colors[type] || 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300'}`}>
      {type.toUpperCase()}
    </span>
  );
}

export function StatusDot({ sub }: { sub: FilterSubscription }) {
  const { t } = useTranslation('filterSubscription');
  if (!sub.last_fetched_at) {
    return <span className="flex items-center gap-1 text-xs text-slate-400"><span className="w-2 h-2 rounded-full bg-slate-400" />{t('list.status.never')}</span>;
  }
  if (sub.last_error) {
    return <span className="flex items-center gap-1 text-xs text-red-500" title={sub.last_error}><span className="w-2 h-2 rounded-full bg-red-500" />{t('list.status.error')}</span>;
  }
  return <span className="flex items-center gap-1 text-xs text-green-500"><span className="w-2 h-2 rounded-full bg-green-500" />{t('list.status.ok')}</span>;
}

export function EntriesPanel({
  entries, isLoading, searchQuery, entryExclusions, onToggleExclusion, isTogglingExclusion,
}: {
  entries: { value: string; reason?: string }[];
  isLoading?: boolean;
  searchQuery?: string;
  entryExclusions?: Set<string>;
  onToggleExclusion?: (value: string) => void;
  isTogglingExclusion?: boolean;
}) {
  const { t } = useTranslation('filterSubscription');
  if (isLoading) return <div className="text-xs text-slate-400 py-2 pl-4">...</div>;
  if (!entries.length) return <div className="text-xs text-slate-400 py-2 pl-4">{t('list.noEntries')}</div>;

  const filtered = searchQuery
    ? entries.filter(e => e.value.includes(searchQuery) || (e.reason && e.reason.toLowerCase().includes(searchQuery.toLowerCase())))
    : entries;

  return (
    <div className="mt-2 max-h-60 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg bg-slate-50 dark:bg-slate-900/50">
      {searchQuery && (
        <div className="px-3 py-1.5 text-xs text-slate-400 border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800">
          {filtered.length} / {entries.length} {t('list.searchResults', 'results')}
        </div>
      )}
      <table className="w-full text-xs">
        <tbody>
          {filtered.slice(0, 500).map((entry, i) => {
            const isExcluded = entryExclusions?.has(entry.value) ?? false;
            return (
              <tr key={i} className={`border-b border-slate-200 dark:border-slate-700 last:border-0 ${isExcluded ? 'opacity-50' : ''}`}>
                <td className={`px-3 py-1.5 font-mono text-slate-700 dark:text-slate-300 whitespace-nowrap ${isExcluded ? 'line-through' : ''}`}>{entry.value}</td>
                <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">{entry.reason || '-'}</td>
                {onToggleExclusion && (
                  <td className="px-3 py-1.5 text-right">
                    <button
                      onClick={() => onToggleExclusion(entry.value)}
                      disabled={isTogglingExclusion}
                      className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                        isExcluded
                          ? 'bg-amber-100 text-amber-700 hover:bg-amber-200 dark:bg-amber-900/40 dark:text-amber-300'
                          : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-400'
                      }`}
                    >
                      {isExcluded ? t('entryExclusions.include') : t('entryExclusions.exclude')}
                    </button>
                  </td>
                )}
              </tr>
            );
          })}
          {filtered.length > 500 && (
            <tr><td colSpan={onToggleExclusion ? 3 : 2} className="px-3 py-1.5 text-center text-slate-400">... +{filtered.length - 500} more</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

import { useState, useCallback, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useEscapeKey } from '../hooks/useEscapeKey';
import {
  fetchFilterSubscriptions,
  fetchFilterSubscription,
  createFilterSubscription,
  updateFilterSubscription,
  deleteFilterSubscription,
  refreshFilterSubscription,
  fetchExclusions,
  addExclusion,
  removeExclusion,
} from '../api/filter-subscriptions';
import { fetchProxyHosts } from '../api/proxy-hosts';
import type {
  FilterSubscription,
  CreateFilterSubscriptionRequest,
  UpdateFilterSubscriptionRequest,
  FilterSubscriptionHostExclusion,
} from '../types/filter-subscription';

// Well-known community blocklists
const PRESET_LISTS = [
  { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', type: 'cidr', description: 'Spamhaus Don\'t Route Or Peer — hijacked IP ranges' },
  { name: 'FireHOL Level 1', url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', type: 'cidr', description: 'FireHOL aggregated threat intelligence (Level 1)' },
  { name: 'Blocklist.de', url: 'https://lists.blocklist.de/lists/all.txt', type: 'ip', description: 'IPs reported for attacks (brute-force, bots, spam)' },
  { name: 'IPsum Level 3', url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', type: 'ip', description: 'IPsum threat intelligence — IPs seen on 3+ blacklists' },
  { name: 'Emerging Threats', url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', type: 'ip', description: 'Emerging Threats compiled block list' },
] as const;

function getRelativeTime(dateStr: string): string {
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

function TypeBadge({ type }: { type: string }) {
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

function StatusDot({ sub }: { sub: FilterSubscription }) {
  const { t } = useTranslation('filterSubscription');
  if (!sub.last_fetched_at) {
    return <span className="flex items-center gap-1 text-xs text-slate-400"><span className="w-2 h-2 rounded-full bg-slate-400" />{t('list.status.never')}</span>;
  }
  if (sub.last_error) {
    return <span className="flex items-center gap-1 text-xs text-red-500" title={sub.last_error}><span className="w-2 h-2 rounded-full bg-red-500" />{t('list.status.error')}</span>;
  }
  return <span className="flex items-center gap-1 text-xs text-green-500"><span className="w-2 h-2 rounded-full bg-green-500" />{t('list.status.ok')}</span>;
}

function RefreshSelector({
  refreshType, refreshValue, onTypeChange, onValueChange,
}: {
  refreshType: string; refreshValue: string;
  onTypeChange: (v: string) => void; onValueChange: (v: string) => void;
}) {
  const { t } = useTranslation('filterSubscription');
  return (
    <div className="flex items-center gap-2">
      <select value={refreshType} onChange={e => { onTypeChange(e.target.value); if (e.target.value === 'interval') onValueChange('24h'); else if (e.target.value === 'daily') onValueChange('03:00'); else onValueChange(''); }}
        className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white">
        <option value="interval">{t('form.refreshTypes.interval')}</option>
        <option value="daily">{t('form.refreshTypes.daily')}</option>
        <option value="cron">{t('form.refreshTypes.cron')}</option>
      </select>
      {refreshType === 'interval' && (
        <select value={refreshValue} onChange={e => onValueChange(e.target.value)}
          className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white">
          <option value="6h">{t('form.intervals.6h')}</option>
          <option value="12h">{t('form.intervals.12h')}</option>
          <option value="24h">{t('form.intervals.24h')}</option>
          <option value="48h">{t('form.intervals.48h')}</option>
        </select>
      )}
      {refreshType === 'daily' && (
        <input type="time" value={refreshValue} onChange={e => onValueChange(e.target.value)}
          className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white" />
      )}
      {refreshType === 'cron' && (
        <input type="text" value={refreshValue} onChange={e => onValueChange(e.target.value)} placeholder="0 3 * * *"
          className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white w-36" />
      )}
    </div>
  );
}

function EntriesPanel({ entries, isLoading, searchQuery }: { entries: { value: string; reason?: string }[]; isLoading?: boolean; searchQuery?: string }) {
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
          {filtered.slice(0, 500).map((entry, i) => (
            <tr key={i} className="border-b border-slate-200 dark:border-slate-700 last:border-0">
              <td className="px-3 py-1.5 font-mono text-slate-700 dark:text-slate-300 whitespace-nowrap">{entry.value}</td>
              <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">{entry.reason || '-'}</td>
            </tr>
          ))}
          {filtered.length > 500 && (
            <tr><td colSpan={2} className="px-3 py-1.5 text-center text-slate-400">... +{filtered.length - 500} more</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function FilterSubscriptionList() {
  const { t } = useTranslation('filterSubscription');
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [settingsTarget, setSettingsTarget] = useState<FilterSubscription | null>(null);
  const [expandedSub, setExpandedSub] = useState<string | null>(null);
  const [entrySearch, setEntrySearch] = useState('');

  // Add URL form state
  const [addUrl, setAddUrl] = useState('');
  const [addName, setAddName] = useState('');
  const [addType, setAddType] = useState('');
  const [addRefreshType, setAddRefreshType] = useState('interval');
  const [addRefreshValue, setAddRefreshValue] = useState('24h');

  const { data: subsData, isLoading: subsLoading } = useQuery({
    queryKey: ['filterSubscriptions'],
    queryFn: () => fetchFilterSubscriptions(),
  });

  const { data: expandedSubDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['filterSubscriptionDetail', expandedSub],
    queryFn: () => fetchFilterSubscription(expandedSub!),
    enabled: !!expandedSub,
  });

  const createMutation = useMutation({
    mutationFn: createFilterSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
      setShowAddModal(false);
      setAddUrl('');
      setAddName('');
      setAddType('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteFilterSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
    },
  });

  const refreshMutation = useMutation({
    mutationFn: refreshFilterSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptionDetail'] });
    },
  });

  const subs = subsData?.data || [];
  const subscribedUrls = useMemo(() => new Set(subs.map(s => s.url)), [subs]);

  // Available presets (not yet subscribed)
  const availablePresets = PRESET_LISTS.filter(p => !subscribedUrls.has(p.url));

  const handleCreate = () => {
    if (!addUrl.trim()) return;
    const data: CreateFilterSubscriptionRequest = { url: addUrl.trim(), refresh_type: addRefreshType, refresh_value: addRefreshValue };
    if (addName.trim()) data.name = addName.trim();
    if (addType) data.type = addType;
    createMutation.mutate(data);
  };

  const handlePresetAdd = (preset: typeof PRESET_LISTS[number]) => {
    createMutation.mutate({
      url: preset.url,
      name: preset.name,
      type: preset.type,
      refresh_type: 'interval',
      refresh_value: '24h',
    });
  };

  const handleDelete = (id: string) => {
    if (window.confirm(t('actions.deleteConfirm'))) {
      deleteMutation.mutate(id);
    }
  };

  const toggleSubExpand = (id: string) => {
    if (expandedSub === id) {
      setExpandedSub(null);
      setEntrySearch('');
    } else {
      setExpandedSub(id);
      setEntrySearch('');
    }
  };

  useEscapeKey(useCallback(() => {
    if (settingsTarget) setSettingsTarget(null);
    else if (showAddModal) setShowAddModal(false);
  }, [settingsTarget, showAddModal]), showAddModal || !!settingsTarget);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t('title')}</h2>
        <button onClick={() => setShowAddModal(true)}
          className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white text-sm">
          {t('list.addUrl')}
        </button>
      </div>

      {/* Presets - only show if there are available presets */}
      {availablePresets.length > 0 && (
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">{t('presets.title')}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {availablePresets.map(preset => (
              <div key={preset.url} className="flex items-center justify-between gap-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm font-medium text-slate-900 dark:text-white truncate">{preset.name}</span>
                    <TypeBadge type={preset.type} />
                  </div>
                  <p className="text-xs text-slate-400 truncate mt-0.5">{preset.description}</p>
                </div>
                <button onClick={() => handlePresetAdd(preset)}
                  disabled={createMutation.isPending}
                  className="px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors bg-cyan-600 hover:bg-cyan-700 text-white shrink-0 disabled:opacity-50">
                  {createMutation.isPending ? '...' : t('presets.add')}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subscription List */}
      {subsLoading ? (
        <div className="flex justify-center py-8">
          <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
        </div>
      ) : subs.length === 0 ? (
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-8 text-center">
          <p className="text-sm text-slate-400">{t('list.empty')}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {subs.map(sub => {
            const isExpanded = expandedSub === sub.id;
            return (
              <div key={sub.id} className="bg-white dark:bg-slate-800 rounded-lg shadow">
                <div className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={`w-1 h-10 rounded-full shrink-0 ${sub.enabled ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-medium text-sm text-slate-900 dark:text-white truncate">{sub.name}</span>
                          <TypeBadge type={sub.type} />
                          <StatusDot sub={sub} />
                        </div>
                        <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5 flex-wrap">
                          <span>{t('catalog.entries', { count: sub.entry_count })}</span>
                          <span>{sub.refresh_type}: {sub.refresh_value}</span>
                          {sub.last_fetched_at && <span>{t('list.lastFetch')}: {getRelativeTime(sub.last_fetched_at)}</span>}
                        </div>
                        {sub.last_error && <p className="text-xs text-red-500 mt-1 truncate max-w-md" title={sub.last_error}>{sub.last_error}</p>}
                        {sub.entry_count > 0 && (
                          <button onClick={() => toggleSubExpand(sub.id)}
                            className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline mt-1">
                            {isExpanded ? t('list.hideEntries') : t('list.showEntries')}
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={() => refreshMutation.mutate(sub.id)}
                        disabled={refreshMutation.isPending && refreshMutation.variables === sub.id}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 disabled:opacity-50">
                        {refreshMutation.isPending && refreshMutation.variables === sub.id ? t('actions.refreshing') : t('actions.refresh')}
                      </button>
                      <button onClick={() => setSettingsTarget(sub)}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600">
                        {t('actions.settings')}
                      </button>
                      <button onClick={() => handleDelete(sub.id)}
                        className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20">
                        {t('actions.delete')}
                      </button>
                    </div>
                  </div>
                </div>
                {isExpanded && (
                  <div className="px-4 pb-4">
                    {/* Search within entries */}
                    <input
                      type="text"
                      value={entrySearch}
                      onChange={e => setEntrySearch(e.target.value)}
                      placeholder={t('list.searchPlaceholder')}
                      className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-xs bg-white dark:bg-slate-700 text-slate-900 dark:text-white mb-2"
                    />
                    <EntriesPanel
                      entries={expandedSubDetail?.entries || []}
                      isLoading={detailLoading}
                      searchQuery={entrySearch}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Add URL Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowAddModal(false)}>
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">{t('list.addUrl')}</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.url')}</label>
                <input type="url" value={addUrl} onChange={e => setAddUrl(e.target.value)} placeholder={t('form.urlPlaceholder')}
                  className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.name')}</label>
                <input type="text" value={addName} onChange={e => setAddName(e.target.value)} placeholder={t('form.namePlaceholder')}
                  className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white" />
              </div>
              <RefreshSelector refreshType={addRefreshType} refreshValue={addRefreshValue} onTypeChange={setAddRefreshType} onValueChange={setAddRefreshValue} />
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setShowAddModal(false)}
                className="px-4 py-2 rounded-lg font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                {t('common:buttons.cancel', 'Cancel')}
              </button>
              <button onClick={handleCreate} disabled={!addUrl.trim() || createMutation.isPending}
                className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white disabled:opacity-50">
                {createMutation.isPending ? '...' : t('common:buttons.save', 'Save')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {settingsTarget && <SettingsModal subscription={settingsTarget} onClose={() => setSettingsTarget(null)} />}
    </div>
  );
}

function SettingsModal({ subscription, onClose }: { subscription: FilterSubscription; onClose: () => void }) {
  const { t } = useTranslation('filterSubscription');
  const queryClient = useQueryClient();
  const [name, setName] = useState(subscription.name);
  const [enabled, setEnabled] = useState(subscription.enabled);
  const [refreshType, setRefreshType] = useState(subscription.refresh_type);
  const [refreshValue, setRefreshValue] = useState(subscription.refresh_value);

  useEscapeKey(onClose);

  const { data: exclusions = [] } = useQuery({
    queryKey: ['filterExclusions', subscription.id],
    queryFn: () => fetchExclusions(subscription.id),
  });

  const { data: hostsData } = useQuery({
    queryKey: ['proxyHostsForExclusion'],
    queryFn: () => fetchProxyHosts(1, 200),
  });

  const updateMutation = useMutation({
    mutationFn: (data: UpdateFilterSubscriptionRequest) => updateFilterSubscription(subscription.id, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] }); onClose(); },
  });

  const addExclMutation = useMutation({
    mutationFn: (hostId: string) => addExclusion(subscription.id, hostId),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['filterExclusions', subscription.id] }); },
  });

  const removeExclMutation = useMutation({
    mutationFn: (hostId: string) => removeExclusion(subscription.id, hostId),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['filterExclusions', subscription.id] }); },
  });

  const excludedHostIds = new Set(exclusions.map((e: FilterSubscriptionHostExclusion) => e.proxy_host_id));
  const hosts = hostsData?.data || [];

  const handleSave = () => {
    updateMutation.mutate({
      name: name !== subscription.name ? name : undefined,
      enabled: enabled !== subscription.enabled ? enabled : undefined,
      refresh_type: refreshType !== subscription.refresh_type ? refreshType : undefined,
      refresh_value: refreshValue !== subscription.refresh_value ? refreshValue : undefined,
    });
  };

  const toggleExclusion = (hostId: string) => {
    if (excludedHostIds.has(hostId)) removeExclMutation.mutate(hostId);
    else addExclMutation.mutate(hostId);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">{t('settings.title')}</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.name')}</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)}
              className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white" />
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('common:buttons.enable', 'Enable')}</span>
            <button onClick={() => setEnabled(!enabled)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${enabled ? 'bg-cyan-600' : 'bg-slate-300 dark:bg-slate-600'}`}>
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.refreshType')}</label>
            <RefreshSelector refreshType={refreshType} refreshValue={refreshValue} onTypeChange={setRefreshType} onValueChange={setRefreshValue} />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('settings.exclusions')}</label>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('settings.exclusionDescription')}</p>
            <div className="max-h-48 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg divide-y divide-slate-200 dark:divide-slate-700">
              {hosts.length === 0 ? (
                <p className="text-xs text-slate-400 p-3">-</p>
              ) : hosts.map(host => (
                <label key={host.id} className="flex items-center gap-3 p-2.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer">
                  <input type="checkbox" checked={excludedHostIds.has(host.id)} onChange={() => toggleExclusion(host.id)}
                    className="rounded border-slate-300 text-cyan-600 focus:ring-cyan-500" />
                  <span className="text-sm text-slate-700 dark:text-slate-300 truncate">
                    {host.domain_names[0]}
                    {excludedHostIds.has(host.id) && <span className="ml-2 text-xs text-amber-500">{t('settings.excluded')}</span>}
                  </span>
                </label>
              ))}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
            {t('common:buttons.cancel', 'Cancel')}
          </button>
          <button onClick={handleSave} disabled={updateMutation.isPending}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white disabled:opacity-50">
            {updateMutation.isPending ? '...' : t('common:buttons.save', 'Save')}
          </button>
        </div>
      </div>
    </div>
  );
}

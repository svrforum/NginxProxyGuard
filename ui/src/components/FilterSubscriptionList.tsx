import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  fetchFilterSubscriptions,
  fetchFilterCatalog,
  subscribeFromCatalog,
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
  FilterCatalogEntry,
  CreateFilterSubscriptionRequest,
  UpdateFilterSubscriptionRequest,
  FilterSubscriptionHostExclusion,
} from '../types/filter-subscription';

type TabType = 'catalog' | 'subscriptions';

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
    return <span className="flex items-center gap-1 text-xs text-red-500"><span className="w-2 h-2 rounded-full bg-red-500" />{t('list.status.error')}</span>;
  }
  return <span className="flex items-center gap-1 text-xs text-green-500"><span className="w-2 h-2 rounded-full bg-green-500" />{t('list.status.ok')}</span>;
}

export default function FilterSubscriptionList() {
  const { t } = useTranslation('filterSubscription');
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('catalog');
  const [showAddModal, setShowAddModal] = useState(false);
  const [settingsTarget, setSettingsTarget] = useState<FilterSubscription | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const [catalogRefreshType, setCatalogRefreshType] = useState('interval');
  const [catalogRefreshValue, setCatalogRefreshValue] = useState('24h');

  // Add URL form state
  const [addUrl, setAddUrl] = useState('');
  const [addName, setAddName] = useState('');
  const [addRefreshType, setAddRefreshType] = useState('interval');
  const [addRefreshValue, setAddRefreshValue] = useState('24h');

  const { data: subsData, isLoading: subsLoading } = useQuery({
    queryKey: ['filterSubscriptions'],
    queryFn: () => fetchFilterSubscriptions(),
  });

  const { data: catalog, isLoading: catalogLoading } = useQuery({
    queryKey: ['filterCatalog'],
    queryFn: fetchFilterCatalog,
    enabled: activeTab === 'catalog',
  });

  const subscribeMutation = useMutation({
    mutationFn: subscribeFromCatalog,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
      queryClient.invalidateQueries({ queryKey: ['filterCatalog'] });
      setSelectedPaths([]);
    },
  });

  const createMutation = useMutation({
    mutationFn: createFilterSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
      setShowAddModal(false);
      setAddUrl('');
      setAddName('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteFilterSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
      queryClient.invalidateQueries({ queryKey: ['filterCatalog'] });
    },
  });

  const refreshMutation = useMutation({
    mutationFn: refreshFilterSubscription,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
    },
  });

  const subs = subsData?.data || [];

  const handleSubscribeCatalog = () => {
    if (selectedPaths.length === 0) return;
    subscribeMutation.mutate({
      paths: selectedPaths,
      refresh_type: catalogRefreshType,
      refresh_value: catalogRefreshValue,
    });
  };

  const handleCreate = () => {
    if (!addUrl.trim()) return;
    const data: CreateFilterSubscriptionRequest = {
      url: addUrl.trim(),
      refresh_type: addRefreshType,
      refresh_value: addRefreshValue,
    };
    if (addName.trim()) data.name = addName.trim();
    createMutation.mutate(data);
  };

  const handleDelete = (id: string) => {
    if (window.confirm(t('actions.deleteConfirm'))) {
      deleteMutation.mutate(id);
    }
  };

  const togglePath = (path: string) => {
    setSelectedPaths(prev =>
      prev.includes(path) ? prev.filter(p => p !== path) : [...prev, path]
    );
  };

  // Group catalog entries by type
  const catalogByType: Record<string, FilterCatalogEntry[]> = {};
  if (catalog?.lists) {
    for (const entry of catalog.lists) {
      if (!catalogByType[entry.type]) catalogByType[entry.type] = [];
      catalogByType[entry.type].push(entry);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t('title')}</h2>
        {activeTab === 'subscriptions' && (
          <button
            onClick={() => setShowAddModal(true)}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white text-sm"
          >
            {t('list.addUrl')}
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-700">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('catalog')}
            className={`pb-2 text-sm font-semibold border-b-2 transition-colors ${activeTab === 'catalog'
              ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            {t('tabs.catalog')}
          </button>
          <button
            onClick={() => setActiveTab('subscriptions')}
            className={`pb-2 text-sm font-semibold border-b-2 transition-colors ${activeTab === 'subscriptions'
              ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            {t('tabs.subscriptions')}
            {subs.length > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-xs bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300">
                {subs.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Catalog Tab */}
      {activeTab === 'catalog' && (
        <div className="space-y-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">{t('catalog.title')}</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">{t('catalog.description')}</p>

            {catalogLoading ? (
              <div className="flex justify-center py-8">
                <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              </div>
            ) : !catalog?.lists?.length ? (
              <p className="text-sm text-slate-400 py-4">{t('catalog.empty')}</p>
            ) : (
              <>
                {Object.entries(catalogByType).map(([type, entries]) => (
                  <div key={type} className="mb-6 last:mb-0">
                    <h4 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2 uppercase tracking-wider">{type}</h4>
                    <div className="space-y-2">
                      {entries.map(entry => (
                        <label
                          key={entry.path}
                          className={`flex items-start gap-3 p-3 rounded-lg border transition-colors cursor-pointer ${
                            entry.subscribed
                              ? 'border-cyan-300 bg-cyan-50/50 dark:border-cyan-700 dark:bg-cyan-900/20'
                              : 'border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={selectedPaths.includes(entry.path)}
                            onChange={() => togglePath(entry.path)}
                            disabled={entry.subscribed}
                            className="mt-1 rounded border-slate-300 text-cyan-600 focus:ring-cyan-500"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm text-slate-900 dark:text-white">{entry.name}</span>
                              <TypeBadge type={entry.type} />
                              {entry.subscribed && (
                                <span className="px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300">
                                  {t('catalog.subscribed')}
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{entry.description}</p>
                            <span className="text-xs text-slate-400">{t('catalog.entries', { count: entry.entry_count })}</span>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}

                {/* Subscribe controls */}
                {selectedPaths.length > 0 && (
                  <div className="flex items-center gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
                    <RefreshSelector
                      refreshType={catalogRefreshType}
                      refreshValue={catalogRefreshValue}
                      onTypeChange={setCatalogRefreshType}
                      onValueChange={setCatalogRefreshValue}
                    />
                    <button
                      onClick={handleSubscribeCatalog}
                      disabled={subscribeMutation.isPending}
                      className="px-4 py-2 rounded-lg font-medium transition-colors bg-cyan-600 hover:bg-cyan-700 text-white text-sm disabled:opacity-50"
                    >
                      {subscribeMutation.isPending ? '...' : t('catalog.subscribe')} ({selectedPaths.length})
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* Subscriptions Tab */}
      {activeTab === 'subscriptions' && (
        <div className="space-y-3">
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
            subs.map(sub => (
              <div key={sub.id} className="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`w-1 h-10 rounded-full ${sub.enabled ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-600'}`} />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm text-slate-900 dark:text-white truncate">{sub.name}</span>
                        <TypeBadge type={sub.type} />
                        <StatusDot sub={sub} />
                      </div>
                      <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5">
                        <span>{t('catalog.entries', { count: sub.entry_count })}</span>
                        <span>{sub.refresh_type}: {sub.refresh_value}</span>
                        {sub.last_fetched_at && (
                          <span>{t('list.lastFetch')}: {getRelativeTime(sub.last_fetched_at)}</span>
                        )}
                      </div>
                      {sub.last_error && (
                        <p className="text-xs text-red-500 mt-1 truncate max-w-md" title={sub.last_error}>{sub.last_error}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => refreshMutation.mutate(sub.id)}
                      disabled={refreshMutation.isPending}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600 disabled:opacity-50"
                      title={t('actions.refresh')}
                    >
                      {t('actions.refresh')}
                    </button>
                    <button
                      onClick={() => setSettingsTarget(sub)}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600"
                      title={t('actions.settings')}
                    >
                      {t('actions.settings')}
                    </button>
                    <button
                      onClick={() => handleDelete(sub.id)}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20"
                      title={t('actions.delete')}
                    >
                      {t('actions.delete')}
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
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
                <input
                  type="url"
                  value={addUrl}
                  onChange={e => setAddUrl(e.target.value)}
                  placeholder={t('form.urlPlaceholder')}
                  className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.name')}</label>
                <input
                  type="text"
                  value={addName}
                  onChange={e => setAddName(e.target.value)}
                  placeholder={t('form.namePlaceholder')}
                  className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                />
              </div>
              <RefreshSelector
                refreshType={addRefreshType}
                refreshValue={addRefreshValue}
                onTypeChange={setAddRefreshType}
                onValueChange={setAddRefreshValue}
              />
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 rounded-lg font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300"
              >
                {t('common:buttons.cancel', 'Cancel')}
              </button>
              <button
                onClick={handleCreate}
                disabled={!addUrl.trim() || createMutation.isPending}
                className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white disabled:opacity-50"
              >
                {createMutation.isPending ? '...' : t('common:buttons.save', 'Save')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {settingsTarget && (
        <SettingsModal
          subscription={settingsTarget}
          onClose={() => setSettingsTarget(null)}
        />
      )}
    </div>
  );
}

function RefreshSelector({
  refreshType,
  refreshValue,
  onTypeChange,
  onValueChange,
}: {
  refreshType: string;
  refreshValue: string;
  onTypeChange: (v: string) => void;
  onValueChange: (v: string) => void;
}) {
  const { t } = useTranslation('filterSubscription');
  return (
    <div className="flex items-center gap-2">
      <select
        value={refreshType}
        onChange={e => {
          onTypeChange(e.target.value);
          if (e.target.value === 'interval') onValueChange('24h');
          else if (e.target.value === 'daily') onValueChange('03:00');
          else onValueChange('');
        }}
        className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
      >
        <option value="interval">{t('form.refreshTypes.interval')}</option>
        <option value="daily">{t('form.refreshTypes.daily')}</option>
        <option value="cron">{t('form.refreshTypes.cron')}</option>
      </select>
      {refreshType === 'interval' && (
        <select
          value={refreshValue}
          onChange={e => onValueChange(e.target.value)}
          className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        >
          <option value="6h">{t('form.intervals.6h')}</option>
          <option value="12h">{t('form.intervals.12h')}</option>
          <option value="24h">{t('form.intervals.24h')}</option>
          <option value="48h">{t('form.intervals.48h')}</option>
        </select>
      )}
      {refreshType === 'daily' && (
        <input
          type="time"
          value={refreshValue}
          onChange={e => onValueChange(e.target.value)}
          className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        />
      )}
      {refreshType === 'cron' && (
        <input
          type="text"
          value={refreshValue}
          onChange={e => onValueChange(e.target.value)}
          placeholder="0 3 * * *"
          className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white w-36"
        />
      )}
    </div>
  );
}

function SettingsModal({
  subscription,
  onClose,
}: {
  subscription: FilterSubscription;
  onClose: () => void;
}) {
  const { t } = useTranslation('filterSubscription');
  const queryClient = useQueryClient();
  const [name, setName] = useState(subscription.name);
  const [enabled, setEnabled] = useState(subscription.enabled);
  const [refreshType, setRefreshType] = useState(subscription.refresh_type);
  const [refreshValue, setRefreshValue] = useState(subscription.refresh_value);

  const { data: exclusions = [] } = useQuery({
    queryKey: ['filterExclusions', subscription.id],
    queryFn: () => fetchExclusions(subscription.id),
  });

  const { data: hostsData } = useQuery({
    queryKey: ['proxyHostsForExclusion'],
    queryFn: () => fetchProxyHosts(1, 200),
  });

  const updateMutation = useMutation({
    mutationFn: (data: UpdateFilterSubscriptionRequest) =>
      updateFilterSubscription(subscription.id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
      onClose();
    },
  });

  const addExclMutation = useMutation({
    mutationFn: (hostId: string) => addExclusion(subscription.id, hostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterExclusions', subscription.id] });
    },
  });

  const removeExclMutation = useMutation({
    mutationFn: (hostId: string) => removeExclusion(subscription.id, hostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterExclusions', subscription.id] });
    },
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
    if (excludedHostIds.has(hostId)) {
      removeExclMutation.mutate(hostId);
    } else {
      addExclMutation.mutate(hostId);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-6 w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">{t('settings.title')}</h3>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.name')}</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
          </div>

          {/* Enabled toggle */}
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('common:buttons.enable', 'Enable')}</span>
            <button
              onClick={() => setEnabled(!enabled)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${enabled ? 'bg-cyan-600' : 'bg-slate-300 dark:bg-slate-600'}`}
            >
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
          </div>

          {/* Refresh settings */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.refreshType')}</label>
            <RefreshSelector
              refreshType={refreshType}
              refreshValue={refreshValue}
              onTypeChange={setRefreshType}
              onValueChange={setRefreshValue}
            />
          </div>

          {/* Host exclusions */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('settings.exclusions')}</label>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('settings.exclusionDescription')}</p>
            <div className="max-h-48 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg divide-y divide-slate-200 dark:divide-slate-700">
              {hosts.length === 0 ? (
                <p className="text-xs text-slate-400 p-3">-</p>
              ) : (
                hosts.map(host => (
                  <label key={host.id} className="flex items-center gap-3 p-2.5 hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={excludedHostIds.has(host.id)}
                      onChange={() => toggleExclusion(host.id)}
                      className="rounded border-slate-300 text-cyan-600 focus:ring-cyan-500"
                    />
                    <span className="text-sm text-slate-700 dark:text-slate-300 truncate">
                      {host.domain_names[0]}
                      {excludedHostIds.has(host.id) && (
                        <span className="ml-2 text-xs text-amber-500">{t('settings.excluded')}</span>
                      )}
                    </span>
                  </label>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300"
          >
            {t('common:buttons.cancel', 'Cancel')}
          </button>
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white disabled:opacity-50"
          >
            {updateMutation.isPending ? '...' : t('common:buttons.save', 'Save')}
          </button>
        </div>
      </div>
    </div>
  );
}

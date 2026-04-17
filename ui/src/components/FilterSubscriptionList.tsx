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
  addEntryExclusion,
  removeEntryExclusion,
} from '../api/filter-subscriptions';
import type {
  FilterSubscription,
  CreateFilterSubscriptionRequest,
} from '../types/filter-subscription';
import {
  PRESET_LISTS,
  TypeBadge,
  StatusDot,
  EntriesPanel,
  getRelativeTime,
} from './filter-subscription/SubscriptionTable';
import { AddSubscriptionModal, SettingsModal } from './filter-subscription/SubscriptionForm';
import { HowItWorks, PresetList } from './filter-subscription/SubscriptionActions';

export default function FilterSubscriptionList() {
  const { t } = useTranslation('filterSubscription');
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [settingsTarget, setSettingsTarget] = useState<FilterSubscription | null>(null);
  const [expandedSub, setExpandedSub] = useState<string | null>(null);
  const [entrySearch, setEntrySearch] = useState('');
  const [showHowItWorks, setShowHowItWorks] = useState(false);

  // Add URL form state
  const [addUrl, setAddUrl] = useState('');
  const [addName, setAddName] = useState('');
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

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateFilterSubscription(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptions'] });
    },
  });

  const entryExclusionMutation = useMutation({
    mutationFn: ({ subscriptionId, value, excluded }: { subscriptionId: string; value: string; excluded: boolean }) =>
      excluded ? removeEntryExclusion(subscriptionId, value) : addEntryExclusion(subscriptionId, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptionDetail'] });
    },
  });

  const entryExclusionSet = useMemo(() => {
    if (!expandedSubDetail?.entry_exclusions) return new Set<string>();
    return new Set(expandedSubDetail.entry_exclusions.map(e => e.value));
  }, [expandedSubDetail]);

  const subs = subsData?.data || [];
  const subscribedUrls = useMemo(() => new Set(subs.map(s => s.url)), [subs]);

  // Available presets (not yet subscribed)
  const availablePresets = PRESET_LISTS.filter(p => !subscribedUrls.has(p.url));

  const handleCreate = () => {
    if (!addUrl.trim()) return;
    const data: CreateFilterSubscriptionRequest = { url: addUrl.trim(), refresh_type: addRefreshType, refresh_value: addRefreshValue };
    if (addName.trim()) data.name = addName.trim();
    createMutation.mutate(data);
  };

  const handlePresetAdd = (preset: (typeof PRESET_LISTS)[number]) => {
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
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white">{t('title')}</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('subtitle')}</p>
        </div>
        <button onClick={() => setShowAddModal(true)}
          className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white text-sm">
          {t('list.addUrl')}
        </button>
      </div>

      {/* How it works */}
      <HowItWorks open={showHowItWorks} onToggle={() => setShowHowItWorks(!showHowItWorks)} />

      {/* Presets */}
      <PresetList availablePresets={availablePresets} isPending={createMutation.isPending} onAdd={handlePresetAdd} />

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
                    <div className="flex items-center gap-3 shrink-0">
                      <button
                        onClick={() => toggleMutation.mutate({ id: sub.id, enabled: !sub.enabled })}
                        disabled={toggleMutation.isPending}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${sub.enabled ? 'bg-cyan-600' : 'bg-slate-300 dark:bg-slate-600'}`}
                        title={sub.enabled ? t('actions.disable') : t('actions.enable')}>
                        <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${sub.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
                      </button>
                      <div className="flex items-center gap-2">
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
                      entryExclusions={entryExclusionSet}
                      onToggleExclusion={(value) => {
                        const isExcluded = entryExclusionSet.has(value);
                        entryExclusionMutation.mutate({ subscriptionId: expandedSub!, value, excluded: isExcluded });
                      }}
                      isTogglingExclusion={entryExclusionMutation.isPending}
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
        <AddSubscriptionModal
          addUrl={addUrl}
          setAddUrl={setAddUrl}
          addName={addName}
          setAddName={setAddName}
          addRefreshType={addRefreshType}
          setAddRefreshType={setAddRefreshType}
          addRefreshValue={addRefreshValue}
          setAddRefreshValue={setAddRefreshValue}
          isPending={createMutation.isPending}
          onSubmit={handleCreate}
          onClose={() => setShowAddModal(false)}
        />
      )}

      {/* Settings Modal */}
      {settingsTarget && <SettingsModal subscription={settingsTarget} onClose={() => setSettingsTarget(null)} />}
    </div>
  );
}

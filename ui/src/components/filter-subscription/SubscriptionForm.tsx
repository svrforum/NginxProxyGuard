import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import {
  updateFilterSubscription,
  fetchExclusions,
  addExclusion,
  removeExclusion,
} from '../../api/filter-subscriptions';
import { fetchProxyHosts } from '../../api/proxy-hosts';
import type {
  FilterSubscription,
  UpdateFilterSubscriptionRequest,
  FilterSubscriptionHostExclusion,
} from '../../types/filter-subscription';

export function RefreshSelector({
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

interface AddSubscriptionModalProps {
  addUrl: string;
  setAddUrl: (v: string) => void;
  addName: string;
  setAddName: (v: string) => void;
  addRefreshType: string;
  setAddRefreshType: (v: string) => void;
  addRefreshValue: string;
  setAddRefreshValue: (v: string) => void;
  isPending: boolean;
  onSubmit: () => void;
  onClose: () => void;
}

export function AddSubscriptionModal({
  addUrl,
  setAddUrl,
  addName,
  setAddName,
  addRefreshType,
  setAddRefreshType,
  addRefreshValue,
  setAddRefreshValue,
  isPending,
  onSubmit,
  onClose,
}: AddSubscriptionModalProps) {
  const { t } = useTranslation('filterSubscription');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>
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
          <button onClick={onClose}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
            {t('common:buttons.cancel', 'Cancel')}
          </button>
          <button onClick={onSubmit} disabled={!addUrl.trim() || isPending}
            className="px-4 py-2 rounded-lg font-medium transition-colors bg-primary-600 hover:bg-primary-700 text-white disabled:opacity-50">
            {isPending ? '...' : t('common:buttons.save', 'Save')}
          </button>
        </div>
      </div>
    </div>
  );
}

export function SettingsModal({ subscription, onClose }: { subscription: FilterSubscription; onClose: () => void }) {
  const { t } = useTranslation('filterSubscription');
  const queryClient = useQueryClient();
  const [name, setName] = useState(subscription.name);
  const [enabled, setEnabled] = useState(subscription.enabled);
  const [excludePrivateIPs, setExcludePrivateIPs] = useState(subscription.exclude_private_ips);
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
      exclude_private_ips: excludePrivateIPs !== subscription.exclude_private_ips ? excludePrivateIPs : undefined,
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
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('settings.excludePrivateIPs')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('settings.excludePrivateIPsDescription')}</p>
            </div>
            <button onClick={() => setExcludePrivateIPs(!excludePrivateIPs)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors shrink-0 ${excludePrivateIPs ? 'bg-cyan-600' : 'bg-slate-300 dark:bg-slate-600'}`}>
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${excludePrivateIPs ? 'translate-x-6' : 'translate-x-1'}`} />
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

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchProxyHosts } from '../api/proxy-hosts';
import { getFail2ban, updateFail2ban } from '../api/security';
import type { ProxyHost } from '../types/proxy-host';
import type { CreateFail2banRequest } from '../types/security';
import { Link } from 'react-router-dom';

export function Fail2banManagement() {
  const { t } = useTranslation('fail2ban');
  const queryClient = useQueryClient();
  const [selectedHost, setSelectedHost] = useState<ProxyHost | null>(null);
  const [editSettings, setEditSettings] = useState<CreateFail2banRequest | null>(null);

  // Fetch all proxy hosts
  const hostsQuery = useQuery({
    queryKey: ['proxy-hosts'],
    queryFn: () => fetchProxyHosts(1, 100),
  });

  // Get hosts with block_exploits or fail2ban potential
  const hosts = hostsQuery.data?.data || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('title')}</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
            {t('subtitle')}
          </p>
        </div>
        <Link
          to="/waf/banned-ips"
          className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
          {t('viewBannedIPs')}
        </Link>
      </div>

      {/* Info Card */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <h3 className="text-sm font-medium text-blue-800 dark:text-blue-300">{t('info.title')}</h3>
            <p className="text-sm text-blue-700 dark:text-blue-400 mt-1">{t('info.description')}</p>
          </div>
        </div>
      </div>

      {/* Host List */}
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-gray-200 dark:border-slate-700 overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-200 dark:border-slate-700 bg-gray-50 dark:bg-slate-800/50">
          <h2 className="text-sm font-medium text-gray-900 dark:text-white">{t('hostList.title')}</h2>
        </div>

        {hostsQuery.isLoading ? (
          <div className="p-8 text-center text-gray-500 dark:text-slate-400">
            <svg className="w-8 h-8 animate-spin mx-auto mb-2" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            {t('common:status.loading')}
          </div>
        ) : hosts.length === 0 ? (
          <div className="p-8 text-center text-gray-500 dark:text-slate-400">
            {t('hostList.empty')}
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-slate-700">
            {hosts.map((host) => (
              <HostFail2banRow
                key={host.id}
                host={host}
                onEdit={(settings) => {
                  setSelectedHost(host);
                  setEditSettings(settings);
                }}
              />
            ))}
          </div>
        )}
      </div>

      {/* Edit Modal */}
      {selectedHost && editSettings && (
        <Fail2banEditModal
          host={selectedHost}
          settings={editSettings}
          onClose={() => {
            setSelectedHost(null);
            setEditSettings(null);
          }}
          onSave={() => {
            queryClient.invalidateQueries({ queryKey: ['fail2ban', selectedHost.id] });
            setSelectedHost(null);
            setEditSettings(null);
          }}
        />
      )}
    </div>
  );
}

function HostFail2banRow({
  host,
  onEdit,
}: {
  host: ProxyHost;
  onEdit: (settings: CreateFail2banRequest) => void;
}) {
  const { t } = useTranslation('fail2ban');
  const queryClient = useQueryClient();

  const settingsQuery = useQuery({
    queryKey: ['fail2ban', host.id],
    queryFn: () => getFail2ban(host.id),
    retry: false,
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) => {
      const currentSettings = settingsQuery.data || {
        max_retries: 5,
        find_time: 600,
        ban_time: 3600,
        fail_codes: '401,403',
        action: 'block',
      };
      return updateFail2ban(host.id, { ...currentSettings, enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fail2ban', host.id] });
    },
  });

  const settings = settingsQuery.data;
  const isEnabled = settings?.enabled || false;

  const handleEdit = () => {
    const currentSettings = settingsQuery.data || {
      enabled: false,
      max_retries: 5,
      find_time: 600,
      ban_time: 3600,
      fail_codes: '401,403',
      action: 'block',
    };
    onEdit(currentSettings);
  };

  return (
    <div className="px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors">
      <div className="flex items-center gap-3 min-w-0">
        <div className={`w-10 h-10 rounded-full flex items-center justify-center ${isEnabled ? 'bg-red-100 dark:bg-red-900/30' : 'bg-gray-100 dark:bg-slate-700'}`}>
          <svg className={`w-5 h-5 ${isEnabled ? 'text-red-600 dark:text-red-400' : 'text-gray-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
        </div>
        <div className="min-w-0">
          <div className="font-medium text-gray-900 dark:text-white truncate">
            {host.domain_names?.[0] || host.id}
          </div>
          <div className="text-xs text-gray-500 dark:text-slate-400 flex items-center gap-2">
            {isEnabled ? (
              <>
                <span className="text-red-600 dark:text-red-400">{t('status.enabled')}</span>
                <span>•</span>
                <span>{t('settings.maxRetries')}: {settings?.max_retries}</span>
                <span>•</span>
                <span>{t('settings.banTime')}: {settings?.ban_time}s</span>
              </>
            ) : (
              <span className="text-gray-400">{t('status.disabled')}</span>
            )}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {settingsQuery.isLoading ? (
          <svg className="w-5 h-5 animate-spin text-gray-400" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
        ) : (
          <>
            <button
              onClick={handleEdit}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              title={t('actions.configure')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </button>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={isEnabled}
                onChange={(e) => toggleMutation.mutate(e.target.checked)}
                disabled={toggleMutation.isPending}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-red-300 dark:peer-focus:ring-red-800 rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-slate-600 peer-checked:bg-red-600"></div>
            </label>
          </>
        )}
      </div>
    </div>
  );
}

function Fail2banEditModal({
  host,
  settings,
  onClose,
  onSave,
}: {
  host: ProxyHost;
  settings: CreateFail2banRequest;
  onClose: () => void;
  onSave: () => void;
}) {
  const { t } = useTranslation('fail2ban');
  const [formData, setFormData] = useState<CreateFail2banRequest>(settings);

  const mutation = useMutation({
    mutationFn: () => updateFail2ban(host.id, formData),
    onSuccess: () => {
      onSave();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-lg mx-4">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {t('editModal.title', { host: host.domain_names?.[0] || host.id })}
          </h2>
        </div>

        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                {t('settings.maxRetries')}
              </label>
              <input
                type="number"
                value={formData.max_retries}
                onChange={(e) => setFormData({ ...formData, max_retries: Number(e.target.value) })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">{t('settings.maxRetriesHelp')}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                {t('settings.findTime')}
              </label>
              <input
                type="number"
                value={formData.find_time}
                onChange={(e) => setFormData({ ...formData, find_time: Number(e.target.value) })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">{t('settings.findTimeHelp')}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                {t('settings.banTime')}
              </label>
              <input
                type="number"
                value={formData.ban_time}
                onChange={(e) => setFormData({ ...formData, ban_time: Number(e.target.value) })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white"
              />
              <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">{t('settings.banTimeHelp')}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                {t('settings.action')}
              </label>
              <select
                value={formData.action}
                onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white"
              >
                <option value="block">{t('settings.actionOptions.block')}</option>
                <option value="log">{t('settings.actionOptions.log')}</option>
                <option value="notify">{t('settings.actionOptions.notify')}</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
              {t('settings.failCodes')}
            </label>
            <input
              type="text"
              value={formData.fail_codes}
              onChange={(e) => setFormData({ ...formData, fail_codes: e.target.value })}
              placeholder="401,403"
              className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white"
            />
            <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">{t('settings.failCodesHelp')}</p>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-gray-200 dark:border-slate-700 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 dark:text-slate-300 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            {t('common:buttons.cancel')}
          </button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? t('common:status.saving') : t('common:buttons.save')}
          </button>
        </div>
      </div>
    </div>
  );
}

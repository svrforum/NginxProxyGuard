import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchProxyHosts } from '../api/proxy-hosts';
import { getFail2ban, updateFail2ban } from '../api/security';
import type { ProxyHost } from '../types/proxy-host';
import type { CreateFail2banRequest } from '../types/security';
import { Link } from 'react-router-dom';
import { ModalShell } from './common/ModalShell';
import { EntityCard, IconButton, EmptyState, StatusPill, PencilIcon } from './common/listui';

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
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">{t('title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
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
      <div className="space-y-3">
        <h2 className="text-sm font-medium text-slate-900 dark:text-white">{t('hostList.title')}</h2>

        {hostsQuery.isLoading ? (
          <div className="flex justify-center items-center py-14">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-600"></div>
          </div>
        ) : hosts.length === 0 ? (
          <EmptyState
            icon={
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            }
          >
            {t('hostList.empty')}
          </EmptyState>
        ) : (
          <div className="space-y-3">
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
    <EntityCard active={isEnabled}>
      <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
        <span
          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
            isEnabled
              ? 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-300'
              : 'bg-slate-100 text-slate-400 dark:bg-slate-700 dark:text-slate-500'
          }`}
        >
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
        </span>

        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold text-slate-900 dark:text-white">
            {host.domain_names?.[0] || host.id}
          </div>
          {isEnabled && (
            <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <span>{t('settings.maxRetries')}: {settings?.max_retries}</span>
              <span>•</span>
              <span>{t('settings.banTime')}: {settings?.ban_time}s</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          {settingsQuery.isLoading ? (
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-slate-400 mx-2"></div>
          ) : (
            <>
              <StatusPill active={isEnabled}>
                {isEnabled ? t('status.enabled') : t('status.disabled')}
              </StatusPill>
              <IconButton onClick={handleEdit} title={t('actions.configure')}>
                <PencilIcon />
              </IconButton>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={isEnabled}
                  onChange={(e) => toggleMutation.mutate(e.target.checked)}
                  disabled={toggleMutation.isPending}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-red-300 dark:peer-focus:ring-red-800 rounded-full peer dark:bg-slate-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-slate-600 peer-checked:bg-red-600"></div>
              </label>
            </>
          )}
        </div>
      </div>
    </EntityCard>
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
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-lg">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {t('editModal.title', { host: host.domain_names?.[0] || host.id })}
          </h2>
        </div>

        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('settings.maxRetries')}
              </label>
              <input
                type="number"
                value={formData.max_retries}
                onChange={(e) => setFormData({ ...formData, max_retries: Number(e.target.value) })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              />
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('settings.maxRetriesHelp')}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('settings.findTime')}
              </label>
              <input
                type="number"
                value={formData.find_time}
                onChange={(e) => setFormData({ ...formData, find_time: Number(e.target.value) })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              />
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('settings.findTimeHelp')}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('settings.banTime')}
              </label>
              <input
                type="number"
                value={formData.ban_time}
                onChange={(e) => setFormData({ ...formData, ban_time: Number(e.target.value) })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              />
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('settings.banTimeHelp')}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('settings.action')}
              </label>
              <select
                value={formData.action}
                onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              >
                <option value="block">{t('settings.actionOptions.block')}</option>
                <option value="log">{t('settings.actionOptions.log')}</option>
                <option value="notify">{t('settings.actionOptions.notify')}</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('settings.failCodes')}
            </label>
            <input
              type="text"
              value={formData.fail_codes}
              onChange={(e) => setFormData({ ...formData, fail_codes: e.target.value })}
              placeholder="401,403"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('settings.failCodesHelp')}</p>
          </div>
        </div>

        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
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
    </ModalShell>
  );
}

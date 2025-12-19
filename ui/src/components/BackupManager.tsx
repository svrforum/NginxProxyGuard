import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  listBackups,
  createBackup,
  deleteBackup,
  restoreBackup,
  getBackupStats,
  downloadBackup,
  uploadAndRestoreBackup,
  getSystemSettings,
  updateSystemSettings,
} from '../api/settings';
import type { Backup, CreateBackupRequest, SystemSettings, UpdateSystemSettingsRequest } from '../types/settings';
import { HelpTip } from './common/HelpTip';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateStr: string, locale?: string): string {
  return new Date(dateStr).toLocaleString(locale);
}

export default function BackupManager() {
  const { t, i18n } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [currentBackupId, setCurrentBackupId] = useState<string | null>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [newBackup, setNewBackup] = useState<CreateBackupRequest>({
    includes_config: true,
    includes_certificates: true,
    includes_database: true,
    description: '',
  });
  const [editedSettings, setEditedSettings] = useState<UpdateSystemSettingsRequest>({});
  const [settingsSaveMessage, setSettingsSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: backups, isLoading } = useQuery({
    queryKey: ['backups'],
    queryFn: () => listBackups(1, 50),
    refetchInterval: 5000, // Refresh to check backup status
  });

  const { data: stats } = useQuery({
    queryKey: ['backupStats'],
    queryFn: getBackupStats,
  });

  // System settings for auto backup
  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const updateSettingsMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      setEditedSettings({});
      setSettingsSaveMessage({ type: 'success', text: t('backupManager.messages.saveSuccess') });
      setTimeout(() => setSettingsSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSettingsSaveMessage({ type: 'error', text: t('backupManager.messages.saveFailed', { error: error.message }) });
      setTimeout(() => setSettingsSaveMessage(null), 5000);
    },
  });

  const handleSettingsChange = (key: keyof UpdateSystemSettingsRequest, value: string | number | boolean | object) => {
    setEditedSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSettingsSave = () => {
    if (Object.keys(editedSettings).length > 0) {
      updateSettingsMutation.mutate(editedSettings);
    }
  };

  const getSettingsValue = <K extends keyof SystemSettings>(key: K): SystemSettings[K] | undefined => {
    if (key in editedSettings) {
      return (editedSettings as Partial<SystemSettings>)[key] as SystemSettings[K];
    }
    return systemSettings?.[key];
  };

  const isSettingsModified = Object.keys(editedSettings).length > 0;

  const createMutation = useMutation({
    mutationFn: createBackup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backupStats'] });
      setShowCreateModal(false);
      setNewBackup({
        includes_config: true,
        includes_certificates: true,
        includes_database: true,
        description: '',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteBackup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backupStats'] });
    },
  });

  const restoreMutation = useMutation({
    mutationFn: restoreBackup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backupStats'] });
      alert(t('backupManager.messages.restoreSuccess'));
    },
    onError: (error: Error) => {
      alert(t('backupManager.messages.restoreFailed', { error: error.message }));
    },
  });

  const uploadRestoreMutation = useMutation({
    mutationFn: uploadAndRestoreBackup,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backupStats'] });
      setShowUploadModal(false);
      setUploadFile(null);
      alert(t('backupManager.messages.uploadSuccess'));
    },
    onError: (error: Error) => {
      alert(t('backupManager.messages.uploadFailed', { error: error.message }));
    },
  });

  const handleCreate = () => {
    createMutation.mutate(newBackup);
  };

  const handleDelete = (id: string) => {
    if (confirm(t('backupManager.confirm.delete'))) {
      deleteMutation.mutate(id);
    }
  };

  const handleRestore = (backup: Backup) => {
    if (confirm(t('backupManager.confirm.restore', { filename: backup.filename }))) {
      restoreMutation.mutate(backup.id);
    }
  };

  const handleUploadRestore = () => {
    if (uploadFile) {
      if (confirm(t('backupManager.confirm.uploadRestore'))) {
        uploadRestoreMutation.mutate(uploadFile);
      }
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.name.endsWith('.tar.gz')) {
        alert(t('backupManager.messages.invalidFormat'));
        return;
      }
      setUploadFile(file);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 rounded text-xs">{t('backupManager.status.completed')}</span>;
      case 'in_progress':
        return <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded text-xs animate-pulse">{t('backupManager.status.inProgress')}</span>;
      case 'failed':
        return <span className="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 rounded text-xs">{t('backupManager.status.failed')}</span>;
      default:
        return <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 rounded text-xs">{status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('backupManager.title')}</h1>
        <div className="flex gap-2">
          <button
            onClick={() => setShowUploadModal(true)}
            className="px-4 py-2 bg-green-600 text-white hover:bg-green-700 rounded-lg"
          >
            {t('backupManager.uploadRestore')}
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-blue-600 text-white hover:bg-blue-700 rounded-lg"
          >
            {t('backupManager.createBackup')}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
          <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.totalBackups')}</p>
          <p className="text-2xl font-bold dark:text-white">{stats?.total_backups || 0}</p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
          <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.totalSize')}</p>
          <p className="text-2xl font-bold dark:text-white">{formatBytes(stats?.total_size || 0)}</p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
          <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.lastBackup')}</p>
          <p className="text-lg font-medium dark:text-white">{stats?.last_backup ? formatDate(stats.last_backup, i18n.language) : t('backupManager.stats.never')}</p>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
          <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.retention')}</p>
          <p className="text-2xl font-bold dark:text-white">{stats?.retention_days || 30} {t('backupManager.stats.days')}</p>
        </div>
      </div>

      {/* Auto Backup Settings */}
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow transition-colors">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2 className="text-lg font-semibold dark:text-white">{t('backupManager.autoBackup.title')}</h2>
          </div>
          <button
            onClick={handleSettingsSave}
            disabled={!isSettingsModified || updateSettingsMutation.isPending}
            className="px-4 py-2 text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-gray-300 transition-colors"
          >
            {updateSettingsMutation.isPending ? t('backupManager.buttons.saving') : t('backupManager.buttons.saveChanges')}
          </button>
        </div>
        <div className="p-4 space-y-4">
          {settingsSaveMessage && (
            <div className={`px-4 py-3 rounded-lg text-sm font-medium ${settingsSaveMessage.type === 'success'
              ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
              : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
              }`}>
              {settingsSaveMessage.text}
            </div>
          )}

          {/* Enable Auto Backup */}
          <label className="flex items-center gap-3 cursor-pointer p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg transition-colors">
            <input
              type="checkbox"
              checked={getSettingsValue('auto_backup_enabled') ?? false}
              onChange={(e) => handleSettingsChange('auto_backup_enabled', e.target.checked)}
              className="w-5 h-5 rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
            />
            <div>
              <span className="text-sm font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-2">
                {t('backupManager.autoBackup.enable')}
                <HelpTip contentKey="help.backup.enable" ns="settings" />
              </span>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{t('backupManager.autoBackup.enableDescription')}</p>
            </div>
          </label>

          {/* Schedule */}
          <div>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2">
              {t('backupManager.autoBackup.schedule')}
              <HelpTip contentKey="help.backup.schedule" ns="settings" />
            </label>
            <input
              type="text"
              value={(editedSettings.auto_backup_schedule ?? systemSettings?.auto_backup_schedule) || '0 2 * * *'}
              onChange={(e) => handleSettingsChange('auto_backup_schedule', e.target.value)}
              className="w-full md:w-64 px-3 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="0 2 * * *"
            />
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {t('backupManager.autoBackup.scheduleHelp', { default: '0 2 * * *' })}
            </p>
          </div>

          {/* Retention Count */}
          <div>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2">
              {t('backupManager.autoBackup.retentionCount')}
              <HelpTip contentKey="help.backup.retention" ns="settings" />
            </label>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="100"
                value={getSettingsValue('backup_retention_count') ?? 10}
                onChange={(e) => handleSettingsChange('backup_retention_count', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-gray-600 rounded-lg text-sm dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-gray-500 dark:text-gray-400">{t('backupManager.autoBackup.count')}</span>
            </div>
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t('backupManager.autoBackup.retentionHelp')}</p>
          </div>
        </div>
      </div>

      {/* Backup List */}
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow transition-colors">
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold dark:text-white">{t('backupManager.history.title')}</h2>
        </div>

        {isLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
          </div>
        ) : backups?.data && backups.data.length > 0 ? (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {backups.data.map((backup) => (
              <div key={backup.id} className="p-4 hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium dark:text-white">{backup.filename}</span>
                      {getStatusBadge(backup.status)}
                    </div>
                    <div className="mt-1 text-sm text-gray-500 dark:text-gray-400 flex flex-wrap gap-4">
                      <span>{formatDate(backup.created_at, i18n.language)}</span>
                      <span>{formatBytes(backup.file_size)}</span>
                      <span className="capitalize">{backup.backup_type}</span>
                    </div>
                    <div className="mt-1 text-sm text-gray-500 dark:text-gray-400 flex gap-2">
                      {backup.includes_config && <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">{t('backupManager.labels.config')}</span>}
                      {backup.includes_certificates && <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">{t('backupManager.labels.certs')}</span>}
                      {backup.includes_database && <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">{t('backupManager.labels.database')}</span>}
                    </div>
                    {backup.description && (
                      <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">{backup.description}</p>
                    )}
                    {backup.error_message && (
                      <p className="mt-1 text-sm text-red-600 dark:text-red-400">{backup.error_message}</p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    {backup.status === 'completed' && (
                      <>
                        <button
                          onClick={() => downloadBackup(backup.id, backup.filename)}
                          className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200 rounded-lg transition-colors"
                        >
                          {t('backupManager.buttons.download')}
                        </button>
                        <button
                          onClick={() => handleRestore(backup)}
                          disabled={restoreMutation.isPending}
                          className="px-3 py-1.5 text-sm bg-amber-100 dark:bg-amber-900/30 hover:bg-amber-200 dark:hover:bg-amber-900/50 text-amber-800 dark:text-amber-400 rounded-lg disabled:opacity-50 transition-colors"
                        >
                          {t('backupManager.buttons.restore')}
                        </button>
                      </>
                    )}
                    <button
                      onClick={() => handleDelete(backup.id)}
                      disabled={deleteMutation.isPending}
                      className="px-3 py-1.5 text-sm bg-red-100 dark:bg-red-900/30 hover:bg-red-200 dark:hover:bg-red-900/50 text-red-800 dark:text-red-400 rounded-lg disabled:opacity-50 transition-colors"
                    >
                      {t('backupManager.buttons.delete')}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            {t('backupManager.history.empty')}
          </div>
        )}
      </div>

      {/* Create Backup Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md p-6 transition-colors">
            <h2 className="text-xl font-bold mb-4 dark:text-white">{t('backupManager.createModal.title')}</h2>

            <div className="space-y-4">
              <div className="space-y-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newBackup.includes_config}
                    onChange={(e) => setNewBackup({ ...newBackup, includes_config: e.target.checked })}
                    className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
                  />
                  <span className="dark:text-gray-300">{t('backupManager.createModal.includeConfig')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newBackup.includes_certificates}
                    onChange={(e) => setNewBackup({ ...newBackup, includes_certificates: e.target.checked })}
                    className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
                  />
                  <span className="dark:text-gray-300">{t('backupManager.createModal.includeCerts')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newBackup.includes_database}
                    onChange={(e) => setNewBackup({ ...newBackup, includes_database: e.target.checked })}
                    className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
                  />
                  <span className="dark:text-gray-300">{t('backupManager.createModal.includeDatabase')}</span>
                </label>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('backupManager.createModal.description')}</label>
                <input
                  type="text"
                  value={newBackup.description || ''}
                  onChange={(e) => setNewBackup({ ...newBackup, description: e.target.value })}
                  placeholder={t('backupManager.createModal.descriptionPlaceholder')}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                {t('backupManager.buttons.cancel')}
              </button>
              <button
                onClick={handleCreate}
                disabled={createMutation.isPending}
                className="px-4 py-2 bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50"
              >
                {createMutation.isPending ? t('backupManager.buttons.creating') : t('backupManager.createBackup')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Upload & Restore Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md p-6 transition-colors">
            <h2 className="text-xl font-bold mb-4 dark:text-white">{t('backupManager.uploadModal.title')}</h2>

            <div className="space-y-4">
              <div className="text-sm text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/30 p-3 rounded-lg border border-amber-200 dark:border-amber-800">
                {t('backupManager.uploadModal.warning')}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">{t('backupManager.uploadModal.selectFile')}</label>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".tar.gz"
                  onChange={handleFileSelect}
                  className="hidden"
                />
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 dark:hover:border-blue-400 transition-colors"
                >
                  {uploadFile ? (
                    <div>
                      <p className="text-gray-800 dark:text-white font-medium">{uploadFile.name}</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">{formatBytes(uploadFile.size)}</p>
                    </div>
                  ) : (
                    <div>
                      <p className="text-gray-500 dark:text-gray-400">{t('backupManager.uploadModal.clickToSelect')}</p>
                      <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">{t('backupManager.uploadModal.dragAndDrop')}</p>
                    </div>
                  )}
                </div>
              </div>

              <div className="text-sm text-gray-500 dark:text-gray-400">
                <p className="font-medium mb-1 dark:text-gray-300">{t('backupManager.uploadModal.restoreInfo')}</p>
                <ul className="list-disc list-inside space-y-0.5">
                  <li>{t('backupManager.uploadModal.items.proxyHosts')}</li>
                  <li>{t('backupManager.uploadModal.items.redirectHosts')}</li>
                  <li>{t('backupManager.uploadModal.items.accessLists')}</li>
                  <li>{t('backupManager.uploadModal.items.certificates')}</li>
                  <li>{t('backupManager.uploadModal.items.wafConfig')}</li>
                  <li>{t('backupManager.uploadModal.items.globalSettings')}</li>
                </ul>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <button
                onClick={() => {
                  setShowUploadModal(false);
                  setUploadFile(null);
                }}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                {t('backupManager.buttons.cancel')}
              </button>
              <button
                onClick={handleUploadRestore}
                disabled={!uploadFile || uploadRestoreMutation.isPending}
                className="px-4 py-2 bg-green-600 text-white hover:bg-green-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {uploadRestoreMutation.isPending ? t('backupManager.buttons.restoring') : t('backupManager.uploadRestore')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

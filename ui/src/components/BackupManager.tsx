import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  listBackups,
  createBackup,
  deleteBackup,
  restoreBackup,
  getBackupStats,
  uploadAndRestoreBackup,
  getSystemSettings,
  updateSystemSettings,
} from '../api/settings';
import type { Backup, CreateBackupRequest, UpdateSystemSettingsRequest } from '../types/settings';
import { BackupStatsCards, BackupList, BackupProgressModal } from './backup/BackupList';
import { CreateBackupModal, UploadRestoreModal } from './backup/BackupActions';
import { BackupScheduleCard } from './backup/BackupScheduleCard';

export default function BackupManager() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [currentBackupId, setCurrentBackupId] = useState<string | null>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
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
    refetchInterval: 60000, // Refresh to check backup status
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

  const isSettingsModified = Object.keys(editedSettings).length > 0;

  const createMutation = useMutation({
    mutationFn: createBackup,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backupStats'] });
      setShowCreateModal(false);
      setCurrentBackupId(data.id);
      setShowProgressModal(true);
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
      <BackupStatsCards
        totalBackups={stats?.total_backups || 0}
        totalSize={stats?.total_size || 0}
        lastBackup={stats?.last_backup}
        retentionDays={stats?.retention_days}
      />

      {/* Auto Backup Settings */}
      <BackupScheduleCard
        systemSettings={systemSettings}
        editedSettings={editedSettings}
        onSettingsChange={handleSettingsChange}
        onSave={handleSettingsSave}
        isModified={isSettingsModified}
        isSaving={updateSettingsMutation.isPending}
        saveMessage={settingsSaveMessage}
      />

      {/* Backup List */}
      <BackupList
        backups={backups?.data}
        isLoading={isLoading}
        restorePending={restoreMutation.isPending}
        deletePending={deleteMutation.isPending}
        onRestore={handleRestore}
        onDelete={handleDelete}
      />

      {/* Create Backup Modal */}
      {showCreateModal && (
        <CreateBackupModal
          newBackup={newBackup}
          setNewBackup={setNewBackup}
          isPending={createMutation.isPending}
          onCreate={handleCreate}
          onClose={() => setShowCreateModal(false)}
        />
      )}

      {/* Upload & Restore Modal */}
      {showUploadModal && (
        <UploadRestoreModal
          uploadFile={uploadFile}
          onFileSelect={handleFileSelect}
          onUploadRestore={handleUploadRestore}
          onClose={() => {
            setShowUploadModal(false);
            setUploadFile(null);
          }}
          isPending={uploadRestoreMutation.isPending}
        />
      )}

      {/* Backup Progress Modal */}
      {showProgressModal && currentBackupId && (
        <BackupProgressModal
          backupId={currentBackupId}
          backups={backups?.data || []}
          onClose={() => {
            setShowProgressModal(false);
            setCurrentBackupId(null);
          }}
        />
      )}
    </div>
  );
}

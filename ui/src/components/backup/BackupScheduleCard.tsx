import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import type { SystemSettings, UpdateSystemSettingsRequest } from '../../types/settings';

interface BackupScheduleCardProps {
  systemSettings?: SystemSettings;
  editedSettings: UpdateSystemSettingsRequest;
  onSettingsChange: (key: keyof UpdateSystemSettingsRequest, value: string | number | boolean | object) => void;
  onSave: () => void;
  isModified: boolean;
  isSaving: boolean;
  saveMessage: { type: 'success' | 'error'; text: string } | null;
}

export function BackupScheduleCard({
  systemSettings,
  editedSettings,
  onSettingsChange,
  onSave,
  isModified,
  isSaving,
  saveMessage,
}: BackupScheduleCardProps) {
  const { t } = useTranslation('settings');

  const getValue = <K extends keyof SystemSettings>(key: K): SystemSettings[K] | undefined => {
    if (key in editedSettings) {
      return (editedSettings as Partial<SystemSettings>)[key] as SystemSettings[K];
    }
    return systemSettings?.[key];
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow transition-colors">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h2 className="text-lg font-semibold dark:text-white">{t('backupManager.autoBackup.title')}</h2>
        </div>
        <button
          onClick={onSave}
          disabled={!isModified || isSaving}
          className="px-4 py-2 text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-gray-300 transition-colors"
        >
          {isSaving ? t('backupManager.buttons.saving') : t('backupManager.buttons.saveChanges')}
        </button>
      </div>
      <div className="p-4 space-y-4">
        {saveMessage && (
          <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
            ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
            }`}>
            {saveMessage.text}
          </div>
        )}

        {/* Enable Auto Backup */}
        <label className="flex items-center gap-3 cursor-pointer p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg transition-colors">
          <input
            type="checkbox"
            checked={getValue('auto_backup_enabled') ?? false}
            onChange={(e) => onSettingsChange('auto_backup_enabled', e.target.checked)}
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
            onChange={(e) => onSettingsChange('auto_backup_schedule', e.target.value)}
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
              value={getValue('backup_retention_count') ?? 10}
              onChange={(e) => onSettingsChange('backup_retention_count', parseInt(e.target.value))}
              className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-gray-300 dark:border-gray-600 rounded-lg text-sm dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <span className="text-sm text-gray-500 dark:text-gray-400">{t('backupManager.autoBackup.count')}</span>
          </div>
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{t('backupManager.autoBackup.retentionHelp')}</p>
        </div>
      </div>
    </div>
  );
}

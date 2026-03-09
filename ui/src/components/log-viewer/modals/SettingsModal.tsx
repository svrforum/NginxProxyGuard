import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useEscapeKey } from '../../../hooks/useEscapeKey';
import { updateLogSettings, cleanupLogs } from '../../../api/logs';
import type { LogSettings } from '../../../types/log';

interface SettingsModalProps {
  settings: LogSettings;
  onClose: () => void;
}

export function SettingsModal({ settings, onClose }: SettingsModalProps) {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const [retentionDays, setRetentionDays] = useState(settings.retention_days);
  const [autoCleanup, setAutoCleanup] = useState(settings.auto_cleanup_enabled);

  useEscapeKey(onClose);

  const updateMutation = useMutation({
    mutationFn: updateLogSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['log-settings'] });
      onClose();
    },
  });

  const cleanupMutation = useMutation({
    mutationFn: cleanupLogs,
    onSuccess: (result) => {
      alert(t('messages.cleanupSuccess', { count: result.deleted }));
      queryClient.invalidateQueries({ queryKey: ['logs'] });
      queryClient.invalidateQueries({ queryKey: ['log-stats'] });
    },
  });

  const handleSave = () => {
    updateMutation.mutate({
      retention_days: retentionDays,
      auto_cleanup_enabled: autoCleanup,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-md w-full">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('settings.title')}</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('settings.retention')}
            </label>
            <input
              type="number"
              value={retentionDays}
              onChange={(e) => setRetentionDays(parseInt(e.target.value) || 30)}
              min={1}
              max={365}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('settings.retentionDesc')}
            </p>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                {t('settings.autoCleanup')}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {t('settings.autoCleanupDesc')}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setAutoCleanup(!autoCleanup)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${autoCleanup ? 'bg-primary-600' : 'bg-slate-200 dark:bg-slate-600'
                }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoCleanup ? 'translate-x-6' : 'translate-x-1'
                  }`}
              />
            </button>
          </div>

          <div className="pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              onClick={() => cleanupMutation.mutate()}
              disabled={cleanupMutation.isPending}
              className="w-full py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg transition-colors"
            >
              {cleanupMutation.isPending ? t('settings.cleaning') : t('settings.cleanupNow')}
            </button>
          </div>
        </div>

        <div className="flex gap-3 p-4 border-t border-slate-200 dark:border-slate-700">
          <button
            onClick={onClose}
            className="flex-1 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
          >
            {t('settings.cancel')}
          </button>
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="flex-1 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors"
          >
            {updateMutation.isPending ? t('settings.saving') : t('settings.save')}
          </button>
        </div>
      </div>
    </div>
  );
}

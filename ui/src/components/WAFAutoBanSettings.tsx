import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getSystemSettings, updateSystemSettings } from '../api/settings';
import type { SystemSettings, UpdateSystemSettingsRequest } from '../types/settings';
import { HelpTip } from './common/HelpTip';

export default function WAFAutoBanSettings() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [editedSettings, setEditedSettings] = useState<UpdateSystemSettingsRequest>({});

  const { data: settings, isLoading } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const updateMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      setEditedSettings({});
    },
  });

  const handleChange = (key: keyof UpdateSystemSettingsRequest, value: string | number | boolean | object) => {
    setEditedSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (Object.keys(editedSettings).length > 0) {
      updateMutation.mutate(editedSettings);
    }
  };

  const getValue = <K extends keyof SystemSettings>(key: K): SystemSettings[K] | undefined => {
    if (key in editedSettings) {
      return (editedSettings as Partial<SystemSettings>)[key] as SystemSettings[K];
    }
    return settings?.[key];
  };

  const isModified = Object.keys(editedSettings).length > 0;

  const inputClass = "mt-1 w-full px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors";

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-white">{t('system.waf.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('system.waf.description')}
          </p>
        </div>
        <button
          onClick={handleSave}
          disabled={!isModified || updateMutation.isPending}
          className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 transition-colors"
        >
          {updateMutation.isPending ? t('system.buttons.saving') : t('system.buttons.save')}
        </button>
      </div>

      {/* Status Card */}
      <div className={`p-5 rounded-xl ${getValue('waf_auto_ban_enabled') ? 'bg-orange-50 dark:bg-orange-900/10 border border-orange-200 dark:border-orange-800' : 'bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700'
        }`}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-slate-800 dark:text-white">{t('system.waf.status.title')}</h3>
            <p className="text-sm mt-1.5 text-slate-600 dark:text-slate-400">
              {getValue('waf_auto_ban_enabled')
                ? t('system.waf.status.activeDescription')
                : t('system.waf.status.inactiveDescription')}
            </p>
          </div>
          <div className={`px-3 py-1.5 rounded-full text-sm font-medium ${getValue('waf_auto_ban_enabled')
            ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300'
            : 'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
            }`}>
            {getValue('waf_auto_ban_enabled') ? t('system.waf.status.active') : t('system.waf.status.inactive')}
          </div>
        </div>
      </div>

      {/* Enable/Disable */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-5">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-sm font-semibold text-slate-800 dark:text-white">{t('system.waf.enable.label')}</h4>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {t('system.waf.enable.description')}
            </p>
          </div>
          <button
            onClick={() => handleChange('waf_auto_ban_enabled', !getValue('waf_auto_ban_enabled'))}
            className={`relative w-12 h-6 rounded-full transition-colors ${getValue('waf_auto_ban_enabled') ? 'bg-orange-500' : 'bg-slate-300 dark:bg-slate-600'
              }`}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${getValue('waf_auto_ban_enabled') ? 'translate-x-6' : ''
              }`}></span>
          </button>
        </div>
      </div>

      {/* Auto-Ban Configuration */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden">
        <div className="p-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('system.waf.config.title')}</h3>
          </div>
        </div>

        <div className="divide-y divide-slate-200 dark:divide-slate-700">
          {/* Threshold */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                {t('system.waf.config.threshold.label')}
                <HelpTip contentKey="help.waf.threshold" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {t('system.waf.config.threshold.description')}
              </p>
            </div>
            <div className="w-24">
              <input
                type="number"
                min="1"
                max="1000"
                value={getValue('waf_auto_ban_threshold') ?? 10}
                onChange={(e) => handleChange('waf_auto_ban_threshold', parseInt(e.target.value) || 10)}
                className={inputClass}
              />
            </div>
          </div>

          {/* Time Window */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                {t('system.waf.config.window.label')}
                <HelpTip contentKey="help.waf.window" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {t('system.waf.config.window.description')}
              </p>
            </div>
            <div className="w-24">
              <input
                type="number"
                min="60"
                max="86400"
                value={getValue('waf_auto_ban_window') ?? 300}
                onChange={(e) => handleChange('waf_auto_ban_window', parseInt(e.target.value) || 300)}
                className={inputClass}
              />
            </div>
          </div>

          {/* Ban Duration */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                {t('system.waf.config.duration.label')}
                <HelpTip contentKey="help.waf.duration" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {t('system.waf.config.duration.description')}
              </p>
            </div>
            <div className="w-24">
              <input
                type="number"
                min="0"
                max="604800"
                value={getValue('waf_auto_ban_duration') ?? 3600}
                onChange={(e) => handleChange('waf_auto_ban_duration', e.target.value === '' ? 3600 : parseInt(e.target.value))}
                className={inputClass}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-xl p-4">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-blue-500 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm text-blue-800 dark:text-blue-300">
            <p className="font-semibold">{t('system.waf.info.title')}</p>
            <p className="mt-1">
              {t('system.waf.info.description')}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

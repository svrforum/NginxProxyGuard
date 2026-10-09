import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  getSystemSettings,
  updateSystemSettings,
} from '../api/settings';
import type { SystemSettings, UpdateSystemSettingsRequest } from '../types/settings';
import { HelpTip } from './common/HelpTip';
import LogRawReclaimCard from './settings/LogRawReclaimCard';

export default function MaintenanceSettings() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [editedSettings, setEditedSettings] = useState<UpdateSystemSettingsRequest>({});
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: settings, isLoading } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const updateMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      setEditedSettings({});
      setSaveMessage({ type: 'success', text: t('messages.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${error.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
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

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  // Pre-calculate retention years/months for display
  const getRetentionDisplay = (days: number, unit: 'years' | 'months') => {
    if (unit === 'years') return `${Math.round(days / 365 * 10) / 10}${t('system.maintenance.retention.years')}`;
    return `${Math.round(days / 30 * 10) / 10}${t('system.maintenance.retention.months')}`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-white">{t('system.maintenance.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('system.maintenance.description')}
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

      {/* Save Message */}
      {saveMessage && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
          }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Log Retention Settings */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
        <div className="flex items-center gap-2 mb-2">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('system.maintenance.retention.title')}</h3>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('system.maintenance.retention.description')}
        </p>

        <div className="bg-slate-50 dark:bg-slate-700/50 rounded-xl border border-slate-200 dark:border-slate-600 divide-y divide-slate-200 dark:divide-slate-600 transition-colors">
          {/* Access Logs */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-blue-500"></div>
                {t('system.maintenance.retention.access')}
                <HelpTip contentKey="help.maintenance.access" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.retention.accessDesc')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('access_log_retention_days') ?? 1095}
                onChange={(e) => handleChange('access_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.retention.days')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded w-16 text-center">
                {getRetentionDisplay(getValue('access_log_retention_days') ?? 1095, 'years')}
              </span>
            </div>
          </div>

          {/* WAF Events */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-red-500"></div>
                {t('system.maintenance.retention.waf')}
                <HelpTip contentKey="help.maintenance.waf" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.retention.wafDesc')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('waf_log_retention_days') ?? 90}
                onChange={(e) => handleChange('waf_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.retention.days')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded w-16 text-center">
                {getRetentionDisplay(getValue('waf_log_retention_days') ?? 90, 'months')}
              </span>
            </div>
          </div>

          {/* Error Logs */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                {t('system.maintenance.retention.error')}
                <HelpTip contentKey="help.maintenance.error" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.retention.errorDesc')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('error_log_retention_days') ?? 30}
                onChange={(e) => handleChange('error_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.retention.days')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded w-16 text-center">
                {getRetentionDisplay(getValue('error_log_retention_days') ?? 30, 'months')}
              </span>
            </div>
          </div>

          {/* System Logs */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-slate-500"></div>
                {t('system.maintenance.retention.system')}
                <HelpTip contentKey="help.maintenance.system" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.retention.systemDesc')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('system_log_retention_days') ?? 30}
                onChange={(e) => handleChange('system_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.retention.days')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded w-16 text-center">
                {getRetentionDisplay(getValue('system_log_retention_days') ?? 30, 'months')}
              </span>
            </div>
          </div>

          {/* Admin Audit */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-purple-500"></div>
                {t('system.maintenance.retention.audit')}
                <HelpTip contentKey="help.maintenance.audit" ns="settings" />
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.retention.auditDesc')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('audit_log_retention_days') ?? 1095}
                onChange={(e) => handleChange('audit_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.retention.days')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded w-16 text-center">
                {getRetentionDisplay(getValue('audit_log_retention_days') ?? 1095, 'years')}
              </span>
            </div>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="mt-4 flex items-center gap-3 flex-wrap">
          <span className="text-sm font-medium text-slate-500 dark:text-slate-400">{t('system.maintenance.presets.label')}</span>
          <button
            type="button"
            onClick={() => {
              handleChange('access_log_retention_days', 1095);
              handleChange('waf_log_retention_days', 90);
              handleChange('error_log_retention_days', 30);
              handleChange('system_log_retention_days', 30);
              handleChange('audit_log_retention_days', 1095);
            }}
            className="px-3 py-1.5 text-sm font-medium text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 hover:bg-blue-100 dark:hover:bg-blue-900/40 rounded-lg transition-colors"
          >
            {t('system.maintenance.presets.default')}
          </button>
          <button
            type="button"
            onClick={() => {
              handleChange('access_log_retention_days', 365);
              handleChange('waf_log_retention_days', 180);
              handleChange('error_log_retention_days', 90);
              handleChange('system_log_retention_days', 90);
              handleChange('audit_log_retention_days', 1825);
            }}
            className="px-3 py-1.5 text-sm font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/30 hover:bg-emerald-100 dark:hover:bg-emerald-900/40 rounded-lg transition-colors"
          >
            {t('system.maintenance.presets.extended')}
          </button>
          <button
            type="button"
            onClick={() => {
              handleChange('access_log_retention_days', 30);
              handleChange('waf_log_retention_days', 30);
              handleChange('error_log_retention_days', 7);
              handleChange('system_log_retention_days', 7);
              handleChange('audit_log_retention_days', 365);
            }}
            className="px-3 py-1.5 text-sm font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/30 hover:bg-amber-100 dark:hover:bg-amber-900/40 rounded-lg transition-colors"
          >
            {t('system.maintenance.presets.minimal')}
          </button>
        </div>
      </div>

      {/* Stats & Backup Retention */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('system.maintenance.other.title')}</h3>
        </div>
        <div className="bg-slate-50 dark:bg-slate-700/50 rounded-xl border border-slate-200 dark:border-slate-600 p-4 transition-colors">
          <div className="flex items-center gap-1 mb-1">
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
              {t('system.maintenance.other.stats.label')}
              <HelpTip contentKey="help.maintenance.stats" ns="settings" />
            </label>
          </div>
          <div className="flex items-center gap-2 mt-2">
            <input
              type="number"
              min="1"
              max="365"
              value={getValue('stats_retention_days') ?? 90}
              onChange={(e) => handleChange('stats_retention_days', parseInt(e.target.value))}
              className="w-24 px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
            />
            <span className="text-sm text-slate-500 dark:text-slate-400">{t('system.maintenance.retention.days')}</span>
          </div>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {t('system.maintenance.other.stats.description')}
          </p>
        </div>

        <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg">
          <p className="text-sm text-blue-700 dark:text-blue-300">
            {t('system.maintenance.other.backupHint')}
          </p>
        </div>
      </div>

      {/* Raw log copies kept in old compressed logs */}
      <LogRawReclaimCard />
    </div>
  );
}

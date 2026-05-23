import { useTranslation } from 'react-i18next';
import type { SystemSettings, UpdateSystemSettingsRequest } from '../../types/settings';
import { HelpTip } from '../common/HelpTip';

interface MaintenanceTabProps {
  settings: SystemSettings | undefined;
  editedSettings: UpdateSystemSettingsRequest;
  getValue: <K extends keyof SystemSettings>(key: K) => SystemSettings[K] | undefined;
  handleChange: (key: keyof UpdateSystemSettingsRequest, value: string | number | boolean | object) => void;
  inputClass: string;
}

export function MaintenanceTab({
  settings,
  editedSettings,
  getValue,
  handleChange,
  inputClass: _inputClass,
}: MaintenanceTabProps) {
  const { t } = useTranslation('settings');

  // Trusted i18n translation content used with dangerouslySetInnerHTML (preserved from original code)
  const autoBackupScheduleHelp = t('system.maintenance.autoBackup.scheduleHelp');

  return (
    <div className="space-y-6">
      {/* Log Retention Settings per Log Type */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white flex items-center gap-2">
            {t('system.maintenance.logRetention.title')}
            <HelpTip contentKey="help.maintenance.logRetention" ns="settings" />
          </h3>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('system.maintenance.logRetention.description')}
        </p>

        <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 divide-y divide-slate-200 dark:divide-slate-700">
          {/* Access Logs */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-blue-500"></div>
                {t('system.maintenance.logRetention.accessLogs.label')}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.logRetention.accessLogs.description')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('access_log_retention_days') ?? 1095}
                onChange={(e) => handleChange('access_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.logRetention.unit')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded w-16 text-center">
                {t('system.maintenance.logRetention.years', { count: Math.round((getValue('access_log_retention_days') ?? 1095) / 365 * 10) / 10 })}
              </span>
            </div>
          </div>

          {/* WAF Events */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-red-500"></div>
                {t('system.maintenance.logRetention.wafEvents.label')}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.logRetention.wafEvents.description')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('waf_log_retention_days') ?? 90}
                onChange={(e) => handleChange('waf_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.logRetention.unit')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded w-16 text-center">
                {t('system.maintenance.logRetention.months', { count: Math.round((getValue('waf_log_retention_days') ?? 90) / 30 * 10) / 10 })}
              </span>
            </div>
          </div>

          {/* Error Logs */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                {t('system.maintenance.logRetention.errorLogs.label')}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.logRetention.errorLogs.description')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('error_log_retention_days') ?? 30}
                onChange={(e) => handleChange('error_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.logRetention.unit')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded w-16 text-center">
                {t('system.maintenance.logRetention.months', { count: Math.round((getValue('error_log_retention_days') ?? 30) / 30 * 10) / 10 })}
              </span>
            </div>
          </div>

          {/* System Logs */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-slate-500"></div>
                {t('system.maintenance.logRetention.systemLogs.label')}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.logRetention.systemLogs.description')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('system_log_retention_days') ?? 30}
                onChange={(e) => handleChange('system_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.logRetention.unit')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded w-16 text-center">
                {t('system.maintenance.logRetention.months', { count: Math.round((getValue('system_log_retention_days') ?? 30) / 30 * 10) / 10 })}
              </span>
            </div>
          </div>

          {/* Admin Audit */}
          <div className="flex items-center justify-between p-4">
            <div className="flex-1">
              <label className="flex items-center gap-2 text-sm font-semibold text-slate-700 dark:text-slate-300">
                <div className="w-2 h-2 rounded-full bg-purple-500"></div>
                {t('system.maintenance.logRetention.adminAudit.label')}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 ml-4">{t('system.maintenance.logRetention.adminAudit.description')}</p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={getValue('audit_log_retention_days') ?? 1095}
                onChange={(e) => handleChange('audit_log_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400 w-8">{t('system.maintenance.logRetention.unit')}</span>
              <span className="text-xs font-medium text-slate-400 dark:text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded w-16 text-center">
                {t('system.maintenance.logRetention.years', { count: Math.round((getValue('audit_log_retention_days') ?? 1095) / 365 * 10) / 10 })}
              </span>
            </div>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="mt-4 flex items-center gap-3 flex-wrap">
          <span className="text-sm font-medium text-slate-500 dark:text-slate-400">{t('system.maintenance.presets.title')}:</span>
          <button
            type="button"
            onClick={() => {
              handleChange('access_log_retention_days', 1095);
              handleChange('waf_log_retention_days', 90);
              handleChange('error_log_retention_days', 30);
              handleChange('system_log_retention_days', 30);
              handleChange('audit_log_retention_days', 1095);
            }}
            className="px-3 py-1.5 text-sm font-medium text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/10 hover:bg-blue-100 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
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
            className="px-3 py-1.5 text-sm font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/10 hover:bg-emerald-100 dark:hover:bg-emerald-900/20 rounded-lg transition-colors"
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
            className="px-3 py-1.5 text-sm font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/10 hover:bg-amber-100 dark:hover:bg-amber-900/20 rounded-lg transition-colors"
          >
            {t('system.maintenance.presets.minimal')}
          </button>
        </div>
      </div>

      {/* Stats & Backup Retention */}
      <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('system.maintenance.otherRetention.title')}</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.otherRetention.stats.label')}</label>
            <div className="flex items-center gap-2 mt-2">
              <input
                type="number"
                min="1"
                max="365"
                value={getValue('stats_retention_days') ?? 90}
                onChange={(e) => handleChange('stats_retention_days', parseInt(e.target.value))}
                className="w-24 px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400">{t('system.maintenance.logRetention.unit')}</span>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t('system.maintenance.otherRetention.stats.description')}
            </p>
          </div>

          <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.otherRetention.backup.label')}</label>
            <div className="flex items-center gap-2 mt-2">
              <input
                type="number"
                min="1"
                max="100"
                value={getValue('backup_retention_count') ?? 10}
                onChange={(e) => handleChange('backup_retention_count', parseInt(e.target.value))}
                className="w-24 px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <span className="text-sm text-slate-500 dark:text-slate-400">{t('system.maintenance.otherRetention.backup.unit')}</span>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t('system.maintenance.otherRetention.backup.description')}
            </p>
          </div>
        </div>
      </div>

      {/* Auto Backup */}
      <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('system.maintenance.autoBackup.title')}</h3>
        </div>

        <div className="py-3 px-4 bg-slate-50 dark:bg-slate-700/30 rounded-lg border border-slate-200 dark:border-slate-700">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={getValue('auto_backup_enabled') ?? false}
              onChange={(e) => handleChange('auto_backup_enabled', e.target.checked)}
              className="mt-0.5 w-5 h-5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 bg-white dark:bg-slate-700"
            />
            <div>
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('system.maintenance.autoBackup.enableLabel')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {t('system.maintenance.autoBackup.enableDescription')}
              </p>
            </div>
          </label>
        </div>

        <div className="mt-5">
          <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.autoBackup.scheduleLabel')}</label>
          <input
            type="text"
            value={(editedSettings.auto_backup_schedule ?? settings?.auto_backup_schedule) || '0 2 * * *'}
            onChange={(e) => handleChange('auto_backup_schedule', e.target.value)}
            className="mt-1 w-full md:w-64 px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg font-mono text-sm text-slate-700 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="0 2 * * *"
          />
          {/* Trusted i18n content */}
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400" dangerouslySetInnerHTML={{ __html: autoBackupScheduleHelp }} />
        </div>
      </div>

      {/* Raw Log Files */}
      <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
        <div className="flex items-center gap-2 mb-2">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white flex items-center gap-2">
            {t('system.maintenance.rawLogs.title')}
            <HelpTip contentKey="help.maintenance.rawLogs" ns="settings" />
          </h3>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('system.maintenance.rawLogs.description')}
        </p>

        <div className="py-3 px-4 bg-emerald-50 dark:bg-emerald-900/10 rounded-lg border border-emerald-200 dark:border-emerald-900/30 mb-5">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-emerald-600 dark:text-emerald-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <span className="text-sm font-semibold text-emerald-800 dark:text-emerald-300">
                {t('system.maintenance.rawLogs.enable.alwaysOnLabel', { defaultValue: 'Raw 로그 저장 항상 활성화' })}
              </span>
              <p className="text-xs text-emerald-700 dark:text-emerald-400 mt-1">
                {t('system.maintenance.rawLogs.enable.alwaysOnDescription', {
                  defaultValue: 'v2.17.1 부터 LogCollector가 /etc/nginx/logs/access_raw.log를 직접 읽기 때문에 raw 로그 저장은 항상 활성화됩니다. 보관 기간 / 회전 / 압축은 아래에서 조정할 수 있습니다.',
                })}
              </p>
            </div>
          </div>
        </div>

        {true && (
          <div className="space-y-5 pl-2 border-l-2 border-blue-200 dark:border-blue-900/30 ml-2">
            {/* Log Rotation Settings */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.rawLogs.maxSize.label')}</label>
                <div className="flex items-center gap-2 mt-2">
                  <input
                    type="number"
                    min="1"
                    max="1000"
                    value={getValue('raw_log_max_size_mb') ?? 100}
                    onChange={(e) => handleChange('raw_log_max_size_mb', parseInt(e.target.value))}
                    className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <span className="text-sm text-slate-500 dark:text-slate-400">MB</span>
                </div>
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('system.maintenance.rawLogs.maxSize.help')}
                </p>
              </div>

              <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.rawLogs.rotateCount.label')}</label>
                <div className="flex items-center gap-2 mt-2">
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={getValue('raw_log_rotate_count') ?? 5}
                    onChange={(e) => handleChange('raw_log_rotate_count', parseInt(e.target.value))}
                    className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <span className="text-sm text-slate-500 dark:text-slate-400">{t('system.maintenance.rawLogs.rotateCount.unit')}</span>
                </div>
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('system.maintenance.rawLogs.rotateCount.help')}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.rawLogs.retention.label')}</label>
                <div className="flex items-center gap-2 mt-2">
                  <input
                    type="number"
                    min="1"
                    max="365"
                    value={getValue('raw_log_retention_days') ?? 7}
                    onChange={(e) => handleChange('raw_log_retention_days', parseInt(e.target.value))}
                    className="w-24 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white text-right focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                  <span className="text-sm text-slate-500 dark:text-slate-400">{t('system.maintenance.logRetention.unit')}</span>
                </div>
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('system.maintenance.rawLogs.retention.help')}
                </p>
              </div>

              <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <div className="py-1">
                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={getValue('raw_log_compress_rotated') ?? true}
                      onChange={(e) => handleChange('raw_log_compress_rotated', e.target.checked)}
                      className="mt-0.5 w-5 h-5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 bg-white dark:bg-slate-700"
                    />
                    <div>
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.maintenance.rawLogs.compress.label')}</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                        {t('system.maintenance.rawLogs.compress.help')}
                      </p>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* Storage Estimate */}
            <div className="p-4 bg-blue-50 dark:bg-blue-900/10 rounded-lg border border-blue-200 dark:border-blue-900/20">
              <div className="flex items-start gap-3">
                <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div className="text-sm text-blue-800 dark:text-blue-300">
                  <p className="font-medium">{t('system.maintenance.rawLogs.storage.title')}</p>
                  <p className="mt-1">
                    {t('system.maintenance.rawLogs.storage.estimate', {
                      size: ((getValue('raw_log_max_size_mb') ?? 100) * (getValue('raw_log_rotate_count') ?? 5) * 2 * (getValue('raw_log_compress_rotated') ? 0.1 : 1)).toFixed(0)
                    })}
                    {getValue('raw_log_compress_rotated') && ` (${t('system.maintenance.rawLogs.storage.compressed')})`}
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

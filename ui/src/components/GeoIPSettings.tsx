import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { HelpTip } from './common/HelpTip';
import {
  getSystemSettings,
  updateSystemSettings,
  getGeoIPStatus,
  triggerGeoIPUpdate,
  getGeoIPHistory,
  type GeoIPUpdateHistory,
} from '../api/settings';
import type { SystemSettings, UpdateSystemSettingsRequest } from '../types/settings';

export default function GeoIPSettings() {
  const { t, i18n } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [editedSettings, setEditedSettings] = useState<UpdateSystemSettingsRequest>({});
  const [showLicenseKey, setShowLicenseKey] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: settings, isLoading } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const { data: geoipStatus, refetch: refetchGeoIP } = useQuery({
    queryKey: ['geoipStatus'],
    queryFn: getGeoIPStatus,
  });

  const { data: historyData, refetch: refetchHistory } = useQuery({
    queryKey: ['geoipHistory'],
    queryFn: () => getGeoIPHistory(1, 10),
    refetchInterval: 60000, // Refresh every 30 seconds
  });

  const updateMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      queryClient.invalidateQueries({ queryKey: ['geoipStatus'] });
      setEditedSettings({});
      setSaveMessage({ type: 'success', text: t('system.geoip.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: t('system.geoip.saveFailed', { error: error.message }) });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  const geoipUpdateMutation = useMutation({
    mutationFn: () => triggerGeoIPUpdate(true),
    onSuccess: () => {
      setSaveMessage({ type: 'success', text: t('system.geoip.updateStarted') });
      refetchHistory();
      setTimeout(() => {
        refetchGeoIP();
        refetchHistory();
        setSaveMessage(null);
      }, 5000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: t('system.geoip.updateFailed', { error: error.message }) });
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

  const inputClass = "mt-1 w-full px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-white">{t('system.tabs.geoip')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('system.geoip.enable.description')}
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

      {/* Status Card */}
      <div className={`rounded-xl shadow-sm border p-5 transition-colors ${geoipStatus?.status === 'active' ? 'border-emerald-200 bg-emerald-50 dark:bg-emerald-900/10 dark:border-emerald-800' :
        geoipStatus?.status === 'error' ? 'border-red-200 bg-red-50 dark:bg-red-900/10 dark:border-red-800' :
          'border-slate-200 bg-white dark:bg-slate-800 dark:border-slate-700'
        }`}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-slate-800 dark:text-white">{t('system.geoip.status.title')}</h3>
            <p className="text-sm mt-1.5">
              {geoipStatus?.status === 'active' && (
                <span className="text-emerald-700 dark:text-emerald-400">
                  {t('system.geoip.status.active')}
                  {geoipStatus.last_updated && t('system.geoip.status.lastUpdated', { date: new Date(geoipStatus.last_updated).toLocaleDateString(i18n.language) })}
                </span>
              )}
              {geoipStatus?.status === 'inactive' && (
                <span className="text-slate-600 dark:text-slate-400">{t('system.geoip.status.inactive')}</span>
              )}
              {geoipStatus?.status === 'error' && (
                <span className="text-red-700 dark:text-red-400">{geoipStatus.error_message || t('system.geoip.status.error')}</span>
              )}
              {geoipStatus?.status === 'updating' && (
                <span className="text-blue-700 dark:text-blue-400">{t('system.geoip.status.updating')}</span>
              )}
            </p>
          </div>
          <button
            onClick={() => geoipUpdateMutation.mutate()}
            disabled={geoipUpdateMutation.isPending || !settings?.maxmind_license_key}
            className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:bg-slate-300 transition-colors"
          >
            {geoipUpdateMutation.isPending ? t('system.buttons.updating') : t('system.buttons.updateNow')}
          </button>
        </div>
        {geoipStatus && (
          <div className="mt-4 flex gap-4 text-sm">
            <span className={`flex items-center gap-1.5 ${geoipStatus.country_db ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`}>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {geoipStatus.country_db ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /> : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />}
              </svg>
              {t('system.geoip.status.countryDb')}
            </span>
            <span className={`flex items-center gap-1.5 ${geoipStatus.asn_db ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`}>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {geoipStatus.asn_db ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /> : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />}
              </svg>
              {t('system.geoip.status.asnDb')}
            </span>
          </div>
        )}
      </div>

      {/* Configuration */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 space-y-6 transition-colors">
        {/* Enable/Disable */}
        <div className="py-3 px-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg border border-slate-200 dark:border-slate-600 transition-colors">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={getValue('geoip_enabled') ?? false}
              onChange={(e) => handleChange('geoip_enabled', e.target.checked)}
              className="mt-0.5 w-5 h-5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 dark:bg-slate-700"
            />
            <div>
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.geoip.enable.label')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {t('system.geoip.enable.description')}
              </p>
            </div>
          </label>
        </div>

        {/* MaxMind Credentials */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
              {t('system.geoip.account.idLabel')}
              <HelpTip contentKey="help.geoip.accountId" ns="settings" />
            </label>
            <input
              type="text"
              value={(editedSettings.maxmind_account_id ?? settings?.maxmind_account_id) || ''}
              onChange={(e) => handleChange('maxmind_account_id', e.target.value)}
              className={inputClass}
              placeholder={t('system.geoip.account.idPlaceholder')}
            />
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline font-medium">
                {t('system.geoip.account.createAccount')}
              </a>
            </p>
          </div>
          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
              {t('system.geoip.account.keyLabel')}
              <HelpTip contentKey="help.geoip.licenseKey" ns="settings" />
            </label>
            <div className="relative mt-1">
              <input
                type={showLicenseKey ? 'text' : 'password'}
                value={(editedSettings.maxmind_license_key ?? settings?.maxmind_license_key) || ''}
                onChange={(e) => handleChange('maxmind_license_key', e.target.value)}
                className="w-full px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors pr-20"
                placeholder={t('system.geoip.account.keyPlaceholder')}
              />
              <button
                type="button"
                onClick={() => setShowLicenseKey(!showLicenseKey)}
                className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-1 text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 bg-slate-100 dark:bg-slate-600 hover:bg-slate-200 dark:hover:bg-slate-500 rounded transition-colors"
              >
                {showLicenseKey ? t('system.buttons.hide') : t('system.buttons.view')}
              </button>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t('system.geoip.account.keyHelp')}
            </p>
          </div>
        </div>

        {/* Auto Update */}
        <div className="space-y-5 border-t border-slate-200 dark:border-slate-700 pt-6">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
            <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {t('system.geoip.autoUpdate.title')}
          </h3>

          <div className="py-3 px-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg border border-slate-200 dark:border-slate-600 transition-colors">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={getValue('geoip_auto_update') ?? true}
                onChange={(e) => handleChange('geoip_auto_update', e.target.checked)}
                className="mt-0.5 w-5 h-5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 dark:bg-slate-700"
              />
              <div>
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{t('system.geoip.autoUpdate.enableLabel')}</span>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {t('system.geoip.autoUpdate.enableDescription')}
                </p>
              </div>
            </label>
          </div>

          <div>
            <label className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2 mb-1">
              {t('system.geoip.autoUpdate.intervalLabel')}
              <HelpTip contentKey="help.geoip.updateInterval" ns="settings" />
            </label>
            <select
              value={(editedSettings.geoip_update_interval ?? settings?.geoip_update_interval) || '7d'}
              onChange={(e) => handleChange('geoip_update_interval', e.target.value)}
              className={`${inputClass} md:w-48`}
            >
              <option value="1d">{t('system.geoip.autoUpdate.intervals.daily')}</option>
              <option value="7d">{t('system.geoip.autoUpdate.intervals.weekly')}</option>
              <option value="30d">{t('system.geoip.autoUpdate.intervals.monthly')}</option>
            </select>
          </div>
        </div>
      </div>

      {/* Update History */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2 mb-4">
          <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {t('system.geoip.history.title', 'Update History')}
        </h3>

        {historyData?.data && historyData.data.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-700">
                  <th className="text-left py-2 px-3 font-medium text-slate-600 dark:text-slate-400">{t('system.geoip.history.date', 'Date')}</th>
                  <th className="text-left py-2 px-3 font-medium text-slate-600 dark:text-slate-400">{t('system.geoip.history.trigger', 'Trigger')}</th>
                  <th className="text-left py-2 px-3 font-medium text-slate-600 dark:text-slate-400">{t('system.geoip.history.status', 'Status')}</th>
                  <th className="text-left py-2 px-3 font-medium text-slate-600 dark:text-slate-400">{t('system.geoip.history.duration', 'Duration')}</th>
                  <th className="text-left py-2 px-3 font-medium text-slate-600 dark:text-slate-400">{t('system.geoip.history.details', 'Details')}</th>
                </tr>
              </thead>
              <tbody>
                {historyData.data.map((item: GeoIPUpdateHistory) => (
                  <tr key={item.id} className="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30">
                    <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">
                      {new Date(item.started_at).toLocaleString(i18n.language)}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        item.trigger_type === 'auto'
                          ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'
                          : 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300'
                      }`}>
                        {item.trigger_type === 'auto' ? t('system.geoip.history.auto', 'Auto') : t('system.geoip.history.manual', 'Manual')}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                        item.status === 'success' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                        item.status === 'failed' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                        item.status === 'running' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                        'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300'
                      }`}>
                        {item.status === 'running' && (
                          <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                        )}
                        {item.status === 'success' ? t('system.geoip.history.success', 'Success') :
                         item.status === 'failed' ? t('system.geoip.history.failed', 'Failed') :
                         item.status === 'running' ? t('system.geoip.history.running', 'Running') :
                         t('system.geoip.history.pending', 'Pending')}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400">
                      {item.duration_ms ? `${(item.duration_ms / 1000).toFixed(1)}s` : '-'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400 max-w-xs truncate">
                      {item.status === 'failed' && item.error_message ? (
                        <span className="text-red-600 dark:text-red-400" title={item.error_message}>
                          {item.error_message.substring(0, 50)}...
                        </span>
                      ) : item.country_db_size ? (
                        <span>DB: {(item.country_db_size / 1024 / 1024).toFixed(1)}MB</span>
                      ) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-slate-500 dark:text-slate-400">
            <svg className="w-12 h-12 mx-auto mb-3 text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-sm">{t('system.geoip.history.empty', 'No update history yet')}</p>
          </div>
        )}
      </div>
    </div>
  );
}

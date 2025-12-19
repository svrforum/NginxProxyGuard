import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { HelpTip } from './common/HelpTip';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getGlobalSettings,
  updateGlobalSettings,
  resetGlobalSettings,
} from '../api/settings';
import type { GlobalSettings as GlobalSettingsType } from '../types/settings';

type TabType = 'worker' | 'http' | 'performance' | 'compression' | 'ssl' | 'timeout' | 'advanced';

export default function GlobalSettings() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('worker');
  const [editedSettings, setEditedSettings] = useState<Partial<GlobalSettingsType>>({});

  const { data: settings, isLoading } = useQuery({
    queryKey: ['globalSettings'],
    queryFn: getGlobalSettings,
  });

  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const updateMutation = useMutation({
    mutationFn: updateGlobalSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['globalSettings'] });
      setEditedSettings({});
      setSaveMessage({ type: 'success', text: t('messages.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${error.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  const resetMutation = useMutation({
    mutationFn: resetGlobalSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['globalSettings'] });
    },
  });

  const handleChange = (key: keyof GlobalSettingsType, value: string | number | boolean) => {
    setEditedSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (Object.keys(editedSettings).length > 0) {
      updateMutation.mutate(editedSettings);
    }
  };

  const getValue = (key: keyof GlobalSettingsType): string | number | boolean | undefined => {
    return editedSettings[key] !== undefined ? editedSettings[key] : settings?.[key];
  };

  const getNumberValue = (key: keyof GlobalSettingsType, defaultValue: number = 0): number => {
    const val = getValue(key);
    return typeof val === 'number' ? val : defaultValue;
  };

  const getStringValue = (key: keyof GlobalSettingsType, defaultValue: string = ''): string => {
    const val = getValue(key);
    return typeof val === 'string' ? val : defaultValue;
  };

  const getBoolValue = (key: keyof GlobalSettingsType): boolean => {
    const val = getValue(key);
    return typeof val === 'boolean' ? val : false;
  };

  const isModified = Object.keys(editedSettings).length > 0;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'worker', label: t('global.tabs.worker'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" /></svg> },
    { id: 'http', label: t('global.tabs.http'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg> },
    { id: 'performance', label: t('global.tabs.performance'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg> },
    { id: 'compression', label: t('global.tabs.compression'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" /></svg> },
    { id: 'ssl', label: t('global.tabs.ssl'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg> },
    { id: 'timeout', label: t('global.tabs.timeout'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> },
    { id: 'advanced', label: t('global.tabs.advanced'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg> },
  ];

  // Helper component for setting field with description
  const SettingField = ({
    settingKey,
    children,
    className = '',
  }: {
    settingKey: string;
    children: React.ReactNode;
    className?: string;
  }) => {
    return (
      <div className={`${className} group`}>
        <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5 flex items-center gap-2">
          {t(`global.fields.${settingKey}.label`)}
          <HelpTip contentKey={`help.global.${settingKey}`} ns="settings" />
        </label>
        {children}
        <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{t(`global.fields.${settingKey}.description`)}</p>
      </div>
    );
  };

  // Helper component for checkbox with description
  const CheckboxField = ({
    settingKey,
    checked,
    onChange,
  }: {
    settingKey: string;
    checked: boolean;
    onChange: (checked: boolean) => void;
  }) => {
    return (
      <div className="py-3 px-4 rounded-lg bg-slate-50 dark:bg-slate-700/30 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            className="mt-0.5 w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 bg-white dark:bg-slate-700"
          />
          <div className="flex-1">
            <span className="text-[13px] font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
              {t(`global.fields.${settingKey}.label`)}
              <HelpTip contentKey={`help.global.${settingKey}`} ns="settings" />
            </span>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">{t(`global.fields.${settingKey}.description`)}</p>
          </div>
        </label>
      </div>
    );
  };

  // Common input class
  const inputClass = "mt-1 w-full px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-white">{t('global.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('global.description')}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-white rounded-lg disabled:opacity-50 transition-colors"
          >
            {t('global.buttons.reset')}
          </button>
          <button
            onClick={handleSave}
            disabled={!isModified || updateMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 dark:disabled:bg-slate-700 dark:disabled:text-slate-500 transition-colors"
          >
            {updateMutation.isPending ? t('global.buttons.saving') : t('global.buttons.save')}
          </button>
        </div>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-900/30'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/30'
          }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Tabs */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700">
        <div className="border-b border-slate-200 dark:border-slate-700 px-2">
          <div className="flex overflow-x-auto gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-[13px] font-semibold whitespace-nowrap border-b-2 transition-all ${activeTab === tab.id
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                  }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {/* Worker Settings */}
          {activeTab === 'worker' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SettingField settingKey="worker_processes">
                  <input
                    type="number"
                    value={getNumberValue('worker_processes', 0)}
                    onChange={(e) => handleChange('worker_processes', parseInt(e.target.value))}
                    className={inputClass}
                    placeholder={t('global.fields.worker_processes.placeholder')}
                  />
                </SettingField>
                <SettingField settingKey="worker_connections">
                  <input
                    type="number"
                    value={getNumberValue('worker_connections', 1024)}
                    onChange={(e) => handleChange('worker_connections', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 border-t border-slate-200 dark:border-slate-700 pt-6">
                <CheckboxField
                  settingKey="multi_accept"
                  checked={getBoolValue('multi_accept')}
                  onChange={(checked) => handleChange('multi_accept', checked)}
                />
                <CheckboxField
                  settingKey="use_epoll"
                  checked={getBoolValue('use_epoll')}
                  onChange={(checked) => handleChange('use_epoll', checked)}
                />
              </div>
            </div>
          )}

          {/* HTTP Settings */}
          {activeTab === 'http' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SettingField settingKey="keepalive_timeout">
                  <input
                    type="number"
                    value={getNumberValue('keepalive_timeout', 65)}
                    onChange={(e) => handleChange('keepalive_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="keepalive_requests">
                  <input
                    type="number"
                    value={getNumberValue('keepalive_requests', 100)}
                    onChange={(e) => handleChange('keepalive_requests', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="client_max_body_size">
                  <input
                    type="text"
                    value={getStringValue('client_max_body_size', '100m')}
                    onChange={(e) => handleChange('client_max_body_size', e.target.value)}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="types_hash_max_size">
                  <input
                    type="number"
                    value={getNumberValue('types_hash_max_size', 2048)}
                    onChange={(e) => handleChange('types_hash_max_size', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-slate-200 dark:border-slate-700 pt-6">
                <CheckboxField
                  settingKey="sendfile"
                  checked={getBoolValue('sendfile')}
                  onChange={(checked) => handleChange('sendfile', checked)}
                />
                <CheckboxField
                  settingKey="tcp_nopush"
                  checked={getBoolValue('tcp_nopush')}
                  onChange={(checked) => handleChange('tcp_nopush', checked)}
                />
                <CheckboxField
                  settingKey="tcp_nodelay"
                  checked={getBoolValue('tcp_nodelay')}
                  onChange={(checked) => handleChange('tcp_nodelay', checked)}
                />
                <CheckboxField
                  settingKey="server_tokens"
                  checked={getBoolValue('server_tokens')}
                  onChange={(checked) => handleChange('server_tokens', checked)}
                />
              </div>
            </div>
          )}

          {/* Performance Settings (Proxy Buffer & File Cache) */}
          {activeTab === 'performance' && (
            <div className="space-y-8">
              {/* Proxy Buffer Section */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                  <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 text-xs rounded">Buffer</span>
                  {t('global.performance.buffer.title')}
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                  {t('global.performance.buffer.description')}
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <SettingField settingKey="proxy_buffer_size">
                    <input
                      type="text"
                      value={getStringValue('proxy_buffer_size', '8k')}
                      onChange={(e) => handleChange('proxy_buffer_size', e.target.value)}
                      className={inputClass}
                      placeholder="8k"
                    />
                  </SettingField>
                  <SettingField settingKey="proxy_buffers">
                    <input
                      type="text"
                      value={getStringValue('proxy_buffers', '8 32k')}
                      onChange={(e) => handleChange('proxy_buffers', e.target.value)}
                      className={inputClass}
                      placeholder="8 32k"
                    />
                  </SettingField>
                  <SettingField settingKey="proxy_busy_buffers_size">
                    <input
                      type="text"
                      value={getStringValue('proxy_busy_buffers_size', '64k')}
                      onChange={(e) => handleChange('proxy_busy_buffers_size', e.target.value)}
                      className={inputClass}
                      placeholder="64k"
                    />
                  </SettingField>
                  <SettingField settingKey="proxy_max_temp_file_size">
                    <input
                      type="text"
                      value={getStringValue('proxy_max_temp_file_size', '1024m')}
                      onChange={(e) => handleChange('proxy_max_temp_file_size', e.target.value)}
                      className={inputClass}
                      placeholder="1024m"
                    />
                  </SettingField>
                  <SettingField settingKey="proxy_temp_file_write_size">
                    <input
                      type="text"
                      value={getStringValue('proxy_temp_file_write_size', '64k')}
                      onChange={(e) => handleChange('proxy_temp_file_write_size', e.target.value)}
                      className={inputClass}
                      placeholder="64k"
                    />
                  </SettingField>
                </div>
              </div>

              {/* Open File Cache Section */}
              <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                  <span className="px-2 py-1 bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300 text-xs rounded">Cache</span>
                  {t('global.performance.openFileCache.title')}
                </h3>
                <CheckboxField
                  settingKey="open_file_cache_enabled"
                  checked={getBoolValue('open_file_cache_enabled')}
                  onChange={(checked) => handleChange('open_file_cache_enabled', checked)}
                />
                {getBoolValue('open_file_cache_enabled') && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                    <SettingField settingKey="open_file_cache_max">
                      <input
                        type="number"
                        value={getNumberValue('open_file_cache_max', 1000)}
                        onChange={(e) => handleChange('open_file_cache_max', parseInt(e.target.value))}
                        className={inputClass}
                        placeholder="1000"
                      />
                    </SettingField>
                    <SettingField settingKey="open_file_cache_inactive">
                      <input
                        type="text"
                        value={getStringValue('open_file_cache_inactive', '20s')}
                        onChange={(e) => handleChange('open_file_cache_inactive', e.target.value)}
                        className={inputClass}
                        placeholder="20s"
                      />
                    </SettingField>
                    <SettingField settingKey="open_file_cache_valid">
                      <input
                        type="text"
                        value={getStringValue('open_file_cache_valid', '30s')}
                        onChange={(e) => handleChange('open_file_cache_valid', e.target.value)}
                        className={inputClass}
                        placeholder="30s"
                      />
                    </SettingField>
                    <SettingField settingKey="open_file_cache_min_uses">
                      <input
                        type="number"
                        value={getNumberValue('open_file_cache_min_uses', 2)}
                        onChange={(e) => handleChange('open_file_cache_min_uses', parseInt(e.target.value))}
                        className={inputClass}
                        placeholder="2"
                      />
                    </SettingField>
                  </div>
                )}
                {getBoolValue('open_file_cache_enabled') && (
                  <div className="mt-4">
                    <CheckboxField
                      settingKey="open_file_cache_errors"
                      checked={getBoolValue('open_file_cache_errors')}
                      onChange={(checked) => handleChange('open_file_cache_errors', checked)}
                    />
                  </div>
                )}
              </div>

              {/* Proxy Buffer Tips */}
              <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-900/20 rounded-lg p-4 text-sm text-blue-800 dark:text-blue-300">
                {t('global.performance.tips')}
              </div>
            </div>
          )}

          {/* Compression Settings (Gzip + Brotli) */}
          {activeTab === 'compression' && (
            <div className="space-y-8">
              {/* Gzip Section */}
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                  <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs rounded">Gzip</span>
                  {t('global.fields.gzip_enabled.label')}
                </h3>
                <CheckboxField
                  settingKey="gzip_enabled"
                  checked={getBoolValue('gzip_enabled')}
                  onChange={(checked) => handleChange('gzip_enabled', checked)}
                />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                  <SettingField settingKey="gzip_comp_level">
                    <input
                      type="number"
                      min="1"
                      max="9"
                      value={getNumberValue('gzip_comp_level', 6)}
                      onChange={(e) => handleChange('gzip_comp_level', parseInt(e.target.value))}
                      className={inputClass}
                    />
                  </SettingField>
                  <SettingField settingKey="gzip_min_length">
                    <input
                      type="number"
                      value={getNumberValue('gzip_min_length', 256)}
                      onChange={(e) => handleChange('gzip_min_length', parseInt(e.target.value))}
                      className={inputClass}
                    />
                  </SettingField>
                </div>
                <div className="mt-4">
                  <SettingField settingKey="gzip_types">
                    <textarea
                      value={getStringValue('gzip_types', '')}
                      onChange={(e) => handleChange('gzip_types', e.target.value)}
                      rows={2}
                      className={`${inputClass} font-mono`}
                    />
                  </SettingField>
                </div>
                <div className="mt-4">
                  <CheckboxField
                    settingKey="gzip_vary"
                    checked={getBoolValue('gzip_vary')}
                    onChange={(checked) => handleChange('gzip_vary', checked)}
                  />
                </div>
              </div>

              {/* Brotli Section */}
              <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                  <span className="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 text-xs rounded">Brotli</span>
                  {t('global.fields.brotli_enabled.label')}
                </h3>
                <CheckboxField
                  settingKey="brotli_enabled"
                  checked={getBoolValue('brotli_enabled')}
                  onChange={(checked) => handleChange('brotli_enabled', checked)}
                />
                <CheckboxField
                  settingKey="brotli_static"
                  checked={getBoolValue('brotli_static')}
                  onChange={(checked) => handleChange('brotli_static', checked)}
                />
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                  <SettingField settingKey="brotli_comp_level">
                    <input
                      type="number"
                      min="1"
                      max="11"
                      value={getNumberValue('brotli_comp_level', 6)}
                      onChange={(e) => handleChange('brotli_comp_level', parseInt(e.target.value))}
                      className={inputClass}
                    />
                  </SettingField>
                  <SettingField settingKey="brotli_min_length">
                    <input
                      type="number"
                      min="0"
                      value={getNumberValue('brotli_min_length', 1000)}
                      onChange={(e) => handleChange('brotli_min_length', parseInt(e.target.value))}
                      className={inputClass}
                    />
                  </SettingField>
                </div>
                <div className="mt-4">
                  <SettingField settingKey="brotli_types">
                    <textarea
                      value={getStringValue('brotli_types', '')}
                      onChange={(e) => handleChange('brotli_types', e.target.value)}
                      rows={2}
                      className={`${inputClass} font-mono`}
                    />
                  </SettingField>
                </div>
              </div>

              {/* Compression Tips */}
              <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-900/20 rounded-lg p-4 text-sm text-blue-800 dark:text-blue-300">
                {t('global.tips.compression')}
              </div>
            </div>
          )}

          {/* SSL/TLS Settings */}
          {activeTab === 'ssl' && (
            <div className="space-y-6">
              <SettingField settingKey="ssl_protocols">
                <input
                  type="text"
                  value={getStringValue('ssl_protocols', 'TLSv1.2 TLSv1.3')}
                  onChange={(e) => handleChange('ssl_protocols', e.target.value)}
                  className={inputClass}
                />
              </SettingField>
              <SettingField settingKey="ssl_ciphers">
                <textarea
                  value={getStringValue('ssl_ciphers', '')}
                  onChange={(e) => handleChange('ssl_ciphers', e.target.value)}
                  rows={3}
                  className={`${inputClass} font-mono`}
                />
              </SettingField>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <SettingField settingKey="ssl_session_cache">
                  <input
                    type="text"
                    value={getStringValue('ssl_session_cache', 'shared:SSL:10m')}
                    onChange={(e) => handleChange('ssl_session_cache', e.target.value)}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="ssl_session_timeout">
                  <input
                    type="text"
                    value={getStringValue('ssl_session_timeout', '1d')}
                    onChange={(e) => handleChange('ssl_session_timeout', e.target.value)}
                    className={inputClass}
                  />
                </SettingField>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-slate-200 dark:border-slate-700 pt-6">
                <CheckboxField
                  settingKey="ssl_prefer_server_ciphers"
                  checked={getBoolValue('ssl_prefer_server_ciphers')}
                  onChange={(checked) => handleChange('ssl_prefer_server_ciphers', checked)}
                />
                <CheckboxField
                  settingKey="ssl_stapling"
                  checked={getBoolValue('ssl_stapling')}
                  onChange={(checked) => handleChange('ssl_stapling', checked)}
                />
                <CheckboxField
                  settingKey="ssl_stapling_verify"
                  checked={getBoolValue('ssl_stapling_verify')}
                  onChange={(checked) => handleChange('ssl_stapling_verify', checked)}
                />
                <CheckboxField
                  settingKey="ssl_session_tickets"
                  checked={getBoolValue('ssl_session_tickets')}
                  onChange={(checked) => handleChange('ssl_session_tickets', checked)}
                />
              </div>
            </div>
          )}

          {/* Timeout Settings */}
          {activeTab === 'timeout' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <SettingField settingKey="client_body_timeout">
                  <input
                    type="number"
                    value={getNumberValue('client_body_timeout', 60)}
                    onChange={(e) => handleChange('client_body_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="client_header_timeout">
                  <input
                    type="number"
                    value={getNumberValue('client_header_timeout', 60)}
                    onChange={(e) => handleChange('client_header_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="send_timeout">
                  <input
                    type="number"
                    value={getNumberValue('send_timeout', 60)}
                    onChange={(e) => handleChange('send_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 border-t border-slate-200 dark:border-slate-700 pt-6">
                <SettingField settingKey="proxy_connect_timeout">
                  <input
                    type="number"
                    value={getNumberValue('proxy_connect_timeout', 60)}
                    onChange={(e) => handleChange('proxy_connect_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="proxy_send_timeout">
                  <input
                    type="number"
                    value={getNumberValue('proxy_send_timeout', 60)}
                    onChange={(e) => handleChange('proxy_send_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
                <SettingField settingKey="proxy_read_timeout">
                  <input
                    type="number"
                    value={getNumberValue('proxy_read_timeout', 60)}
                    onChange={(e) => handleChange('proxy_read_timeout', parseInt(e.target.value))}
                    className={inputClass}
                  />
                </SettingField>
              </div>
            </div>
          )}

          {/* Advanced Settings */}
          {activeTab === 'advanced' && (
            <div className="space-y-6">
              {/* Direct IP Access Settings */}
              <div className="border-b border-slate-200 dark:border-slate-700 pb-6">
                <div className="flex items-center gap-2 mb-4">
                  <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                  </svg>
                  <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('global.advanced.directIpAccess.title')}</h3>
                </div>

                <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                  {t('global.advanced.directIpAccess.description')}
                </p>

                <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                  <div className="space-y-3">
                    <label className="flex items-start gap-3 p-3 rounded-lg border border-transparent hover:bg-white dark:hover:bg-slate-700 hover:border-slate-200 dark:hover:border-slate-600 cursor-pointer transition-colors">
                      <input
                        type="radio"
                        name="direct_ip_access"
                        checked={getStringValue('direct_ip_access_action', 'allow') === 'allow'}
                        onChange={() => handleChange('direct_ip_access_action', 'allow')}
                        className="mt-0.5 w-4 h-4 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700 border-slate-300 dark:border-slate-600"
                      />
                      <div>
                        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('global.advanced.directIpAccess.options.allow.label')}</span>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          {t('global.advanced.directIpAccess.options.allow.description')}
                        </p>
                      </div>
                    </label>

                    <label className="flex items-start gap-3 p-3 rounded-lg border border-transparent hover:bg-white dark:hover:bg-slate-700 hover:border-slate-200 dark:hover:border-slate-600 cursor-pointer transition-colors">
                      <input
                        type="radio"
                        name="direct_ip_access"
                        checked={getStringValue('direct_ip_access_action', 'allow') === 'block_403'}
                        onChange={() => handleChange('direct_ip_access_action', 'block_403')}
                        className="mt-0.5 w-4 h-4 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700 border-slate-300 dark:border-slate-600"
                      />
                      <div>
                        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('global.advanced.directIpAccess.options.block403.label')}</span>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          {t('global.advanced.directIpAccess.options.block403.description')}
                        </p>
                      </div>
                    </label>

                    <label className="flex items-start gap-3 p-3 rounded-lg border border-transparent hover:bg-white dark:hover:bg-slate-700 hover:border-slate-200 dark:hover:border-slate-600 cursor-pointer transition-colors">
                      <input
                        type="radio"
                        name="direct_ip_access"
                        checked={getStringValue('direct_ip_access_action', 'allow') === 'block_444'}
                        onChange={() => handleChange('direct_ip_access_action', 'block_444')}
                        className="mt-0.5 w-4 h-4 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700 border-slate-300 dark:border-slate-600"
                      />
                      <div>
                        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('global.advanced.directIpAccess.options.block444.label')}</span>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          {t('global.advanced.directIpAccess.options.block444.description')}
                        </p>
                      </div>
                    </label>
                  </div>
                </div>

                <div className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-900/20 rounded-xl p-4 mt-4">
                  <div className="flex gap-3">
                    <svg className="w-5 h-5 text-amber-500 dark:text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div className="text-sm text-amber-800 dark:text-amber-300">
                      <p className="font-semibold">{t('global.advanced.directIpAccess.note.title')}</p>
                      <p className="mt-1">
                        {t('global.advanced.directIpAccess.note.description')}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <SettingField settingKey="resolver">
                <input
                  type="text"
                  value={getStringValue('resolver', '8.8.8.8 8.8.4.4 valid=300s')}
                  onChange={(e) => handleChange('resolver', e.target.value)}
                  className={inputClass}
                />
              </SettingField>
              <SettingField settingKey="error_log_level">
                <select
                  value={getStringValue('error_log_level', 'warn')}
                  onChange={(e) => handleChange('error_log_level', e.target.value)}
                  className={inputClass}
                >
                  <option value="debug">{t('global.advanced.errorLogLevels.debug')}</option>
                  <option value="info">{t('global.advanced.errorLogLevels.info')}</option>
                  <option value="notice">{t('global.advanced.errorLogLevels.notice')}</option>
                  <option value="warn">{t('global.advanced.errorLogLevels.warn')}</option>
                  <option value="error">{t('global.advanced.errorLogLevels.error')}</option>
                  <option value="crit">{t('global.advanced.errorLogLevels.crit')}</option>
                </select>
              </SettingField>
              <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
                <CheckboxField
                  settingKey="access_log_enabled"
                  checked={getBoolValue('access_log_enabled')}
                  onChange={(checked) => handleChange('access_log_enabled', checked)}
                />
              </div>
              <SettingField settingKey="custom_http_config">
                <textarea
                  value={getStringValue('custom_http_config', '')}
                  onChange={(e) => handleChange('custom_http_config', e.target.value)}
                  rows={5}
                  className={`${inputClass} font-mono`}
                  placeholder={t('global.advanced.customConfigPlaceholder')}
                />
              </SettingField>

              {/* DDoS Protection Settings */}
              <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
                <div className="flex items-center gap-2 mb-4">
                  <svg className="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('global.advanced.ddos.title')}</h3>
                </div>

                <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                  {t('global.advanced.ddos.description')}
                </p>

                {/* Connection Limiting */}
                <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4 mb-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-2">
                        {t('global.advanced.ddos.connectionLimit.title')}
                        <HelpTip contentKey="help.global.ddos.connectionLimit" ns="settings" />
                      </span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{t('global.advanced.ddos.connectionLimit.description')}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={getBoolValue('limit_conn_enabled')}
                        onChange={(e) => handleChange('limit_conn_enabled', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-200 dark:bg-slate-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>

                  {getBoolValue('limit_conn_enabled') && (
                    <div className="grid grid-cols-2 gap-4 mt-3 pt-3 border-t border-slate-200 dark:border-slate-700">
                      <div>
                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.connectionLimit.perIp')}</label>
                        <input
                          type="number"
                          min="1"
                          max="10000"
                          value={getNumberValue('limit_conn_per_ip', 100)}
                          onChange={(e) => handleChange('limit_conn_per_ip', parseInt(e.target.value) || 100)}
                          className={inputClass}
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.connectionLimit.zoneSize')}</label>
                        <input
                          type="text"
                          value={getStringValue('limit_conn_zone_size', '10m')}
                          onChange={(e) => handleChange('limit_conn_zone_size', e.target.value)}
                          className={inputClass}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Request Limiting */}
                <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4 mb-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-2">
                        {t('global.advanced.ddos.requestLimit.title')}
                        <HelpTip contentKey="help.global.ddos.requestLimit" ns="settings" />
                      </span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{t('global.advanced.ddos.requestLimit.description')}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={getBoolValue('limit_req_enabled')}
                        onChange={(e) => handleChange('limit_req_enabled', e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-gray-200 dark:bg-slate-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>

                  {getBoolValue('limit_req_enabled') && (
                    <div className="grid grid-cols-3 gap-4 mt-3 pt-3 border-t border-slate-200 dark:border-slate-700">
                      <div>
                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.requestLimit.rate')}</label>
                        <input
                          type="number"
                          min="1"
                          max="10000"
                          value={getNumberValue('limit_req_rate', 20)}
                          onChange={(e) => handleChange('limit_req_rate', parseInt(e.target.value) || 20)}
                          className={inputClass}
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.requestLimit.burst')}</label>
                        <input
                          type="number"
                          min="0"
                          max="1000"
                          value={getNumberValue('limit_req_burst', 10)}
                          onChange={(e) => handleChange('limit_req_burst', parseInt(e.target.value) || 10)}
                          className={inputClass}
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.requestLimit.zoneSize')}</label>
                        <input
                          type="text"
                          value={getStringValue('limit_req_zone_size', '10m')}
                          onChange={(e) => handleChange('limit_req_zone_size', e.target.value)}
                          className={inputClass}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {/* Bandwidth Limiting */}
                <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4 mb-4">
                  <div className="mb-3">
                    <span className="text-sm font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-2">
                      {t('global.advanced.ddos.bandwidthLimit.title')}
                      <HelpTip contentKey="help.global.ddos.bandwidthLimit" ns="settings" />
                    </span>
                    <p className="text-xs text-slate-500 dark:text-slate-400">{t('global.advanced.ddos.bandwidthLimit.description')}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.bandwidthLimit.rate')}</label>
                      <input
                        type="number"
                        min="0"
                        value={getNumberValue('limit_rate', 0)}
                        onChange={(e) => handleChange('limit_rate', parseInt(e.target.value) || 0)}
                        className={inputClass}
                        placeholder="0 (unlimited)"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('global.advanced.ddos.bandwidthLimit.after')}</label>
                      <input
                        type="text"
                        value={getStringValue('limit_rate_after', '')}
                        onChange={(e) => handleChange('limit_rate_after', e.target.value)}
                        className={inputClass}
                        placeholder="500k, 1m"
                      />
                    </div>
                  </div>
                </div>

                {/* Warning for nginx.conf level settings */}
                <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-900/20 rounded-xl p-4 mt-4">
                  <div className="flex gap-3">
                    <svg className="w-5 h-5 text-blue-500 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div className="text-sm text-blue-800 dark:text-blue-300">
                      <p className="font-semibold">{t('global.advanced.nginxConfNote.title')}</p>
                      <p className="mt-1">
                        {t('global.advanced.nginxConfNote.description')}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Reset Timedout Connection */}
                <div className="mt-4">
                  <CheckboxField
                    settingKey="reset_timedout_connection"
                    checked={getBoolValue('reset_timedout_connection')}
                    onChange={(checked) => handleChange('reset_timedout_connection', checked)}
                  />
                </div>
              </div>

              {/* Resolver Timeout */}
              <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
                <SettingField settingKey="resolver_timeout">
                  <input
                    type="text"
                    value={getStringValue('resolver_timeout', '30s')}
                    onChange={(e) => handleChange('resolver_timeout', e.target.value)}
                    className={inputClass}
                    placeholder="30s"
                  />
                </SettingField>
              </div>

              {/* Custom Stream Config */}
              <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
                <SettingField settingKey="custom_stream_config">
                  <textarea
                    value={getStringValue('custom_stream_config', '')}
                    onChange={(e) => handleChange('custom_stream_config', e.target.value)}
                    rows={5}
                    className={`${inputClass} font-mono`}
                    placeholder={t('global.advanced.customStreamConfigPlaceholder')}
                  />
                </SettingField>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

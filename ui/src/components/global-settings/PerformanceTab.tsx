import { useTranslation } from 'react-i18next';
import { SettingField, CheckboxField, inputClass } from './SettingFields';
import type { TabContentProps } from './types';

export default function PerformanceTab({ getStringValue, getNumberValue, getBoolValue, handleChange }: TabContentProps) {
  const { t } = useTranslation('settings');

  return (
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
          <SettingField settingKey="proxy_buffering">
            <select
              value={getStringValue('proxy_buffering', '')}
              onChange={(e) => handleChange('proxy_buffering', e.target.value)}
              className={inputClass}
            >
              <option value="">{t('global.performance.buffer.useNginxDefault', 'Use nginx default (on)')}</option>
              <option value="on">{t('global.performance.buffer.bufferingOn', 'On (buffer responses)')}</option>
              <option value="off">{t('global.performance.buffer.bufferingOff', 'Off (stream directly)')}</option>
            </select>
            {getStringValue('proxy_buffering', '') === 'off' && (
              <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                {t('global.performance.buffer.bufferingOffCacheNote')}
              </p>
            )}
          </SettingField>
          <SettingField settingKey="proxy_request_buffering">
            <select
              value={getStringValue('proxy_request_buffering', '')}
              onChange={(e) => handleChange('proxy_request_buffering', e.target.value)}
              className={inputClass}
            >
              <option value="">{t('global.performance.buffer.useNginxDefault', 'Use nginx default (on)')}</option>
              <option value="on">{t('global.performance.buffer.requestBufferingOn', 'On (buffer entire request)')}</option>
              <option value="off">{t('global.performance.buffer.requestBufferingOff', 'Off (stream to upstream)')}</option>
            </select>
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
  );
}

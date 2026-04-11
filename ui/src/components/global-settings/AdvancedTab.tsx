import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import { SettingField, CheckboxField, inputClass } from './SettingFields';
import ErrorPageLanguageSection from './ErrorPageLanguageSection';
import type { TabContentProps } from './types';

export default function AdvancedTab({ getStringValue, getNumberValue, getBoolValue, handleChange }: TabContentProps) {
  const { t } = useTranslation('settings');

  return (
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

      {/* IPv6 Settings */}
      <div className="border-b border-slate-200 dark:border-slate-700 pb-6">
        <div className="flex items-center gap-2 mb-4">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('global.advanced.ipv6.title')}</h3>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
          {t('global.advanced.ipv6.description')}
        </p>
        <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('global.advanced.ipv6.enabled')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('global.advanced.ipv6.enabledDescription')}</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={getBoolValue('enable_ipv6')}
                onChange={(e) => handleChange('enable_ipv6', e.target.checked)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-200 dark:bg-slate-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
            </label>
          </div>
        </div>
        <div className="bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-900/20 rounded-xl p-4 mt-4">
          <div className="flex gap-3">
            <svg className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <p className="text-sm text-amber-800 dark:text-amber-300">{t('global.advanced.ipv6.warning')}</p>
          </div>
        </div>
      </div>

      {/* Public Error Page Language (system_settings) */}
      <ErrorPageLanguageSection />

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
  );
}

import type { CreateProxyHostRequest } from '../../../types/proxy-host'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../common/HelpTip'

interface PerformanceTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
}

export function PerformanceTabContent({ formData, setFormData }: PerformanceTabProps) {
  const { t } = useTranslation('proxyHost')
  return (
    <div className="space-y-6">
      {/* Caching */}
      <div className={`p-4 rounded-lg border-2 transition-colors ${formData.cache_enabled ? 'bg-indigo-50 border-indigo-200 dark:bg-indigo-900/20 dark:border-indigo-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
        }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.cache_enabled ? 'bg-indigo-100 dark:bg-indigo-900/40' : 'bg-slate-200 dark:bg-slate-700'
              }`}>
              <svg className={`w-5 h-5 ${formData.cache_enabled ? 'text-indigo-600 dark:text-indigo-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
              </svg>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex items-center h-5 mt-1">
                <input
                  type="checkbox"
                  checked={formData.cache_enabled}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, cache_enabled: e.target.checked }))
                  }
                  className="w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.performance.cache.enabled')}
                  <HelpTip contentKey="help.performance.cache" />
                </label>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {t('form.performance.cache.description')}
                </p>
              </div>
            </div>
          </div>
        </div>
        {formData.cache_enabled && (
          <div className="mt-4 space-y-4 bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
            {/* Static Only Toggle */}
            <div className="flex items-center justify-between">
              <div className="flex-1">
                <label className="text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.performance.cache.staticOnly', 'Static Assets Only')}
                  <HelpTip contentKey="help.performance.cacheStaticOnly" />
                </label>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  {t('form.performance.cache.staticOnlyDesc', 'Only cache static files (js, css, images, fonts). API paths are always excluded.')}
                </p>
              </div>
              <input
                type="checkbox"
                checked={formData.cache_static_only ?? true}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, cache_static_only: e.target.checked }))
                }
                className="w-4 h-4 text-indigo-600 rounded border-slate-300 focus:ring-indigo-500"
              />
            </div>

            {/* Cache TTL */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5 flex items-center gap-2">
                {t('form.performance.cache.ttl', 'Cache Duration')}
                <HelpTip contentKey="help.performance.cacheTTL" />
              </label>
              <select
                value={formData.cache_ttl || '7d'}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, cache_ttl: e.target.value }))
                }
                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                <option value="30m">{t('form.performance.cache.ttl30m', '30 minutes')}</option>
                <option value="1h">{t('form.performance.cache.ttl1h', '1 hour')}</option>
                <option value="6h">{t('form.performance.cache.ttl6h', '6 hours')}</option>
                <option value="1d">{t('form.performance.cache.ttl1d', '1 day')}</option>
                <option value="7d">{t('form.performance.cache.ttl7d', '7 days')}</option>
                <option value="30d">{t('form.performance.cache.ttl30d', '30 days')}</option>
              </select>
            </div>

            {/* Cache Info */}
            <div className="text-xs text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/50 p-3 rounded border border-slate-200 dark:border-slate-700">
              <p className="font-medium text-slate-600 dark:text-slate-300 mb-1">{t('form.performance.cache.info', 'Cache behavior:')}</p>
              <ul className="list-disc list-inside space-y-0.5">
                <li>{formData.cache_static_only
                  ? t('form.performance.cache.infoStaticOnly', 'Only static assets (js, css, images, fonts) will be cached')
                  : t('form.performance.cache.infoAll', 'All responses except /api/* paths will be cached')}</li>
                <li>{t('form.performance.cache.infoTTL', 'Cache duration:')} {formData.cache_ttl || '7d'}</li>
                <li>{t('form.performance.cache.infoHeader', 'X-Cache-Status header shows HIT/MISS')}</li>
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* WebSocket */}
      <div className={`p-4 rounded-lg border-2 transition-colors ${formData.allow_websocket_upgrade ? 'bg-cyan-50 border-cyan-200 dark:bg-cyan-900/20 dark:border-cyan-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
        }`}>
        <label className="flex items-center justify-between cursor-pointer">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.allow_websocket_upgrade ? 'bg-cyan-100 dark:bg-cyan-900/40' : 'bg-slate-200 dark:bg-slate-700'
              }`}>
              <svg className={`w-5 h-5 ${formData.allow_websocket_upgrade ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
            </div>
            <div>
              <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                {t('form.basic.websocket')}
                <HelpTip contentKey="help.performance.websocket" />
              </span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.basic.websocketDescription')}</p>
            </div>
          </div>
          <input
            type="checkbox"
            checked={formData.allow_websocket_upgrade}
            onChange={(e) =>
              setFormData((prev) => ({
                ...prev,
                allow_websocket_upgrade: e.target.checked,
              }))
            }
            className="rounded border-slate-300 text-cyan-600 focus:ring-cyan-500 h-5 w-5"
          />
        </label>
      </div>

      {/* Proxy Settings Override */}
      <div className="p-4 rounded-lg border-2 border-slate-200 bg-slate-50 dark:bg-slate-800/50 dark:border-slate-700">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full flex items-center justify-center bg-amber-100 dark:bg-amber-900/40">
            <svg className="w-5 h-5 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </div>
          <div>
            <h3 className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
              {t('form.performance.proxySettings.title', 'Proxy Settings Override')}
              <HelpTip contentKey="help.performance.proxyOverride" />
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {t('form.performance.proxySettings.description', 'Override global settings for this host. Leave empty to use global values.')}
            </p>
          </div>
        </div>

        <div className="space-y-4 bg-white dark:bg-slate-800 p-4 rounded-lg border border-slate-200 dark:border-slate-700">
          {/* Client Max Body Size */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5 flex items-center gap-2">
              {t('form.performance.proxySettings.clientMaxBodySize', 'Client Max Body Size')}
              <HelpTip contentKey="help.performance.clientMaxBodySize" />
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={formData.client_max_body_size || ''}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, client_max_body_size: e.target.value }))
                }
                placeholder={t('form.performance.proxySettings.useGlobal', 'Use global setting')}
                className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-amber-500"
              />
              <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                {t('form.performance.proxySettings.example', 'e.g.')} 100m, 1g, 0
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('form.performance.proxySettings.clientMaxBodySizeDesc', 'Maximum allowed size of client request body. Use 0 for unlimited.')}
            </p>
          </div>

          {/* Proxy Max Temp File Size */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5 flex items-center gap-2">
              {t('form.performance.proxySettings.proxyMaxTempFileSize', 'Proxy Max Temp File Size')}
              <HelpTip contentKey="help.performance.proxyMaxTempFileSize" />
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={formData.proxy_max_temp_file_size || ''}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, proxy_max_temp_file_size: e.target.value }))
                }
                placeholder={t('form.performance.proxySettings.useGlobal', 'Use global setting')}
                className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-amber-500"
              />
              <span className="text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                {t('form.performance.proxySettings.example', 'e.g.')} 1024m, 0
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('form.performance.proxySettings.proxyMaxTempFileSizeDesc', 'Maximum size of temp file for buffering. Use 0 for unlimited (large downloads).')}
            </p>
          </div>

          {/* Proxy Buffering */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5 flex items-center gap-2">
              {t('form.performance.proxySettings.proxyBuffering', 'Proxy Buffering')}
              <HelpTip contentKey="help.performance.proxyBuffering" />
            </label>
            <select
              value={formData.proxy_buffering || ''}
              onChange={(e) =>
                setFormData((prev) => ({ ...prev, proxy_buffering: e.target.value }))
              }
              className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-amber-500"
            >
              <option value="">{t('form.performance.proxySettings.useGlobal', 'Use global setting')}</option>
              <option value="on">{t('form.performance.proxySettings.bufferingOn', 'On (buffer responses)')}</option>
              <option value="off">{t('form.performance.proxySettings.bufferingOff', 'Off (stream directly)')}</option>
            </select>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('form.performance.proxySettings.proxyBufferingDesc', 'Disable buffering for real-time streaming or very large file transfers.')}
            </p>
          </div>

          {/* Info box */}
          <div className="text-xs text-slate-500 dark:text-slate-400 bg-amber-50 dark:bg-amber-900/20 p-3 rounded border border-amber-200 dark:border-amber-800">
            <p className="font-medium text-amber-700 dark:text-amber-300 mb-1">
              {t('form.performance.proxySettings.infoTitle', 'Large file transfer tips:')}
            </p>
            <ul className="list-disc list-inside space-y-0.5">
              <li>{t('form.performance.proxySettings.infoUpload', 'For large uploads: increase client_max_body_size (e.g., 10g or 0 for unlimited)')}</li>
              <li>{t('form.performance.proxySettings.infoDownload', 'For large downloads: set proxy_max_temp_file_size to 0')}</li>
              <li>{t('form.performance.proxySettings.infoStreaming', 'For streaming: set proxy_buffering to off')}</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

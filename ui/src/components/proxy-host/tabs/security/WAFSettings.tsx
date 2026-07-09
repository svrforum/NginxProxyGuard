import type { CreateProxyHostRequest } from '../../../../types/proxy-host'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'
import { InheritOverrideControl, type InheritOverrideValue } from '../../../common/InheritOverrideControl'
import { WAFFields } from './WAFFields'

interface WAFSettingsProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
}

export function WAFSettings({ formData, setFormData }: WAFSettingsProps) {
  const { t } = useTranslation('proxyHost')

  // Tri-state (#198 slice 6):
  //   waf_use_global=true          → inherit  (host follows the global WAF default)
  //   waf_use_global=false + on    → override (host uses its own mode/paranoia)
  //   waf_use_global=false + off   → disable  (WAF off regardless of the global default)
  const mode: InheritOverrideValue = formData.waf_use_global
    ? 'inherit'
    : formData.waf_enabled
      ? 'override'
      : 'disable'

  const handleModeChange = (value: InheritOverrideValue) => {
    if (value === 'override') {
      setFormData((prev) => ({ ...prev, waf_use_global: false, waf_enabled: true }))
    } else if (value === 'disable') {
      setFormData((prev) => ({ ...prev, waf_use_global: false, waf_enabled: false }))
    } else {
      setFormData((prev) => ({ ...prev, waf_use_global: true }))
    }
  }

  const active = mode === 'override'

  return (
    <div className={`p-4 rounded-lg border-2 transition-colors ${active ? 'bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'}`}>
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-10 h-10 rounded-full flex items-center justify-center ${active ? 'bg-purple-100 dark:bg-purple-900/40' : 'bg-slate-200 dark:bg-slate-700'}`}>
          <svg className={`w-5 h-5 ${active ? 'text-purple-600 dark:text-purple-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
              {t('form.waf.title')}
              <HelpTip contentKey="help.security.waf" />
            </span>
            {active && (
              <span className={`px-1.5 py-0.5 text-xs font-medium rounded ${formData.waf_mode === 'blocking' ? 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300' : 'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300'}`}>
                {formData.waf_mode === 'blocking' ? t('form.waf.modeBlocking') : t('form.waf.modeDetection')}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.waf.description')}</p>
        </div>
      </div>

      <InheritOverrideControl value={mode} onChange={handleModeChange} />

      {mode === 'inherit' && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('form.waf.inheritHint')}</p>
      )}
      {mode === 'disable' && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('form.waf.disableHint')}</p>
      )}

      {mode === 'override' && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-purple-200 dark:border-purple-800">
          <WAFFields
            values={{
              waf_mode: formData.waf_mode ?? 'blocking',
              waf_paranoia_level: formData.waf_paranoia_level ?? 1,
              waf_anomaly_threshold: formData.waf_anomaly_threshold ?? 5,
            }}
            onChange={(patch) => setFormData((prev) => ({ ...prev, ...patch } as CreateProxyHostRequest))}
          />
        </div>
      )}
    </div>
  )
}

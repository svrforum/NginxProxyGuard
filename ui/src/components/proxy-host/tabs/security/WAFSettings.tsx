import type { CreateProxyHostRequest } from '../../../../types/proxy-host'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'

interface WAFSettingsProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
}

export function WAFSettings({ formData, setFormData }: WAFSettingsProps) {
  const { t } = useTranslation('proxyHost')
  return (
    <div className={`p-4 rounded-lg border-2 transition-colors ${formData.waf_enabled ? 'bg-purple-50 dark:bg-purple-900/20 border-purple-200 dark:border-purple-800' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'
      }`}>
      <label className="flex items-center justify-between cursor-pointer">

        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.waf_enabled ? 'bg-purple-100 dark:bg-purple-900/40' : 'bg-slate-200 dark:bg-slate-700'
            }`}>
            <svg className={`w-5 h-5 ${formData.waf_enabled ? 'text-purple-600 dark:text-purple-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                {t('form.waf.title')}
                <HelpTip contentKey="help.security.waf" />
              </span>
              {formData.waf_enabled && (
                <span className={`px-1.5 py-0.5 text-xs font-medium rounded ${formData.waf_mode === 'blocking' ? 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300' : 'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300'
                  }`}>
                  {formData.waf_mode === 'blocking' ? t('form.waf.modeBlocking') : t('form.waf.modeDetection')}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.waf.description')}</p>
          </div>
        </div>
        <input
          type="checkbox"
          checked={formData.waf_enabled}
          onChange={(e) =>
            setFormData((prev) => ({
              ...prev,
              waf_enabled: e.target.checked,
            }))
          }
          className="rounded border-slate-300 dark:border-slate-600 text-purple-600 focus:ring-purple-500 h-5 w-5 dark:bg-slate-700"
        />
      </label>

      {formData.waf_enabled && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-purple-200 dark:border-purple-800">
          {/* Memory Recommendation Warning */}
          <div className="mb-4 p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
            <div className="flex items-start gap-2">
              <svg className="w-5 h-5 text-amber-500 dark:text-amber-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <div>
                <p className="text-sm font-medium text-amber-800 dark:text-amber-200">{t('form.waf.memoryWarningTitle')}</p>
                <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">{t('form.waf.memoryWarningDescription')}</p>
              </div>
            </div>
          </div>

          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{t('form.waf.mode')}</label>
          <div className="flex gap-3">
            <label className={`flex-1 p-3 rounded-lg border cursor-pointer transition-colors ${formData.waf_mode === 'blocking' ? 'bg-purple-100 dark:bg-purple-900/40 border-purple-300 dark:border-purple-700' : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-600'
              }`}>
              <input
                type="radio"
                name="waf_mode"
                value="blocking"
                checked={formData.waf_mode === 'blocking'}
                onChange={() => setFormData(prev => ({ ...prev, waf_mode: 'blocking' }))}
                className="sr-only"
              />
              <div className="text-center">
                <span className="block text-sm font-medium text-slate-900 dark:text-white">{t('form.waf.modeBlocking')}</span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">{t('form.waf.modeBlockingDescription')}</span>
              </div>
            </label>
            <label className={`flex-1 p-3 rounded-lg border cursor-pointer transition-colors ${formData.waf_mode === 'detection' ? 'bg-amber-100 dark:bg-amber-900/40 border-amber-300 dark:border-amber-700' : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-600'
              }`}>
              <input
                type="radio"
                name="waf_mode"
                value="detection"
                checked={formData.waf_mode === 'detection'}
                onChange={() => setFormData(prev => ({ ...prev, waf_mode: 'detection' }))}
                className="sr-only"
              />
              <div className="text-center">
                <span className="block text-sm font-medium text-slate-900 dark:text-white">{t('form.waf.modeDetection')}</span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">{t('form.waf.modeDetectionDescription')}</span>
              </div>
            </label>
          </div>

          {/* Paranoia Level */}
          <div className="mt-4">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('form.waf.paranoiaLevel')}
              <span className="ml-2 text-xs text-slate-500 dark:text-slate-400 font-normal">
                ({t('form.waf.paranoiaLevelDescription')})
              </span>
            </label>
            <div className="grid grid-cols-4 gap-2">
              {[1, 2, 3, 4].map((level) => (
                <label
                  key={level}
                  className={`p-2 rounded-lg border cursor-pointer transition-colors text-center ${formData.waf_paranoia_level === level
                    ? 'bg-purple-100 dark:bg-purple-900/40 border-purple-300 dark:border-purple-700'
                    : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-600'
                    }`}
                >
                  <div className="sr-only">
                    <input
                      type="radio"
                      name="waf_paranoia_level"
                      value={level}
                      checked={formData.waf_paranoia_level === level}
                      onChange={() => setFormData(prev => ({ ...prev, waf_paranoia_level: level }))}
                    />
                  </div>
                  <span className="block text-sm font-bold text-slate-900 dark:text-white">PL{level}</span>
                  <span className="block text-xs text-slate-500 dark:text-slate-400">
                    {level === 1 && '표준'}
                    {level === 2 && '중간'}
                    {level === 3 && '높음'}
                    {level === 4 && '최대'}
                  </span>
                </label>
              ))}
            </div>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              PL1: 일반 사이트 권장 | PL2: 보안 중요 | PL3: 금융/의료 | PL4: 전문가 전용
            </p>
          </div>

          {/* Anomaly Threshold */}
          <div className="mt-4">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('form.waf.anomalyThreshold')}
              <span className="ml-2 text-xs text-slate-500 dark:text-slate-400 font-normal">
                ({t('form.waf.anomalyThresholdDescription')})
              </span>
            </label>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min="1"
                max="20"
                value={formData.waf_anomaly_threshold}
                onChange={(e) => setFormData(prev => ({ ...prev, waf_anomaly_threshold: parseInt(e.target.value) }))}
                className="flex-1 h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-purple-600"
              />
              <span className="w-12 text-center text-sm font-mono bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded dark:text-white">
                {formData.waf_anomaly_threshold}
              </span>
            </div>
            <div className="flex justify-between text-xs text-slate-500 dark:text-slate-400 mt-1">
              <span>엄격 (3)</span>
              <span>표준 (5)</span>
              <span>관대 (10+)</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

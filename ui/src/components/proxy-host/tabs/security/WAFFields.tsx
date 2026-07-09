import { useTranslation } from 'react-i18next'

// The WAF tuning fields shared by the per-host override (WAFSettings) and the
// global default manager (#198 slice 6). waf_enabled / waf_use_global are the
// caller's tri-state concern; this component only edits mode/paranoia/threshold.
export interface WAFFieldValues {
  waf_mode: string
  waf_paranoia_level: number
  waf_anomaly_threshold: number
}

interface WAFFieldsProps {
  values: WAFFieldValues
  onChange: (patch: Partial<WAFFieldValues>) => void
}

export function WAFFields({ values, onChange }: WAFFieldsProps) {
  const { t } = useTranslation('proxyHost')

  return (
    <div>
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
        <label className={`flex-1 p-3 rounded-lg border cursor-pointer transition-colors ${values.waf_mode === 'blocking' ? 'bg-purple-100 dark:bg-purple-900/40 border-purple-300 dark:border-purple-700' : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-600'
          }`}>
          <input
            type="radio"
            name="waf_mode"
            value="blocking"
            checked={values.waf_mode === 'blocking'}
            onChange={() => onChange({ waf_mode: 'blocking' })}
            className="sr-only"
          />
          <div className="text-center">
            <span className="block text-sm font-medium text-slate-900 dark:text-white">{t('form.waf.modeBlocking')}</span>
            <span className="block text-xs text-slate-500 dark:text-slate-400">{t('form.waf.modeBlockingDescription')}</span>
          </div>
        </label>
        <label className={`flex-1 p-3 rounded-lg border cursor-pointer transition-colors ${values.waf_mode === 'detection' ? 'bg-amber-100 dark:bg-amber-900/40 border-amber-300 dark:border-amber-700' : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-600'
          }`}>
          <input
            type="radio"
            name="waf_mode"
            value="detection"
            checked={values.waf_mode === 'detection'}
            onChange={() => onChange({ waf_mode: 'detection' })}
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
              className={`p-2 rounded-lg border cursor-pointer transition-colors text-center ${values.waf_paranoia_level === level
                ? 'bg-purple-100 dark:bg-purple-900/40 border-purple-300 dark:border-purple-700'
                : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-600'
                }`}
            >
              <div className="sr-only">
                <input
                  type="radio"
                  name="waf_paranoia_level"
                  value={level}
                  checked={values.waf_paranoia_level === level}
                  onChange={() => onChange({ waf_paranoia_level: level })}
                />
              </div>
              <span className="block text-sm font-bold text-slate-900 dark:text-white">PL{level}</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {level === 1 && t('form.waf.paranoiaLabels.standard')}
                {level === 2 && t('form.waf.paranoiaLabels.medium')}
                {level === 3 && t('form.waf.paranoiaLabels.high')}
                {level === 4 && t('form.waf.paranoiaLabels.max')}
              </span>
            </label>
          ))}
        </div>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          {t('form.waf.paranoiaHint')}
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
            value={values.waf_anomaly_threshold}
            onChange={(e) => onChange({ waf_anomaly_threshold: parseInt(e.target.value) })}
            className="flex-1 h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer accent-purple-600"
          />
          <span className="w-12 text-center text-sm font-mono bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded dark:text-white">
            {values.waf_anomaly_threshold}
          </span>
        </div>
        <div className="flex justify-between text-xs text-slate-500 dark:text-slate-400 mt-1">
          <span>{t('form.waf.thresholdStrict')}</span>
          <span>{t('form.waf.thresholdStandard')}</span>
          <span>{t('form.waf.thresholdLenient')}</span>
        </div>
      </div>
    </div>
  )
}

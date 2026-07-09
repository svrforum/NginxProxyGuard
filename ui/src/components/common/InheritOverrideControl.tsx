import { useTranslation } from 'react-i18next'

export type InheritOverrideValue = 'inherit' | 'override' | 'disable'

interface InheritOverrideControlProps {
  value: InheritOverrideValue
  onChange: (value: InheritOverrideValue) => void
  /**
   * Optional i18n key for a label rendered above the control. May be a
   * cross-namespace key (e.g. "proxyHost:form.security.geoip.inheritLabel").
   */
  labelKey?: string
}

const OPTIONS: InheritOverrideValue[] = ['inherit', 'override', 'disable']

/**
 * Generic 3-way segmented radio for "inherit global default / override with
 * local config / disable entirely" tri-state settings. Intentionally free of
 * any feature-specific text so it can be reused across features — the option
 * labels come from the shared `common:inheritOverride.*` keys.
 */
export function InheritOverrideControl({ value, onChange, labelKey }: InheritOverrideControlProps) {
  const { t } = useTranslation('common')

  return (
    <div>
      {labelKey && (
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
          {t(labelKey)}
        </label>
      )}
      <div
        role="radiogroup"
        className="inline-flex w-full gap-1 rounded-lg bg-slate-100 dark:bg-slate-700/50 p-1"
      >
        {OPTIONS.map((opt) => {
          const active = value === opt
          return (
            <button
              key={opt}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => onChange(opt)}
              className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                active
                  ? 'bg-white dark:bg-slate-800 text-primary-600 dark:text-primary-400 shadow-sm'
                  : 'text-slate-600 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
              }`}
            >
              {t(`inheritOverride.${opt}`)}
            </button>
          )
        })}
      </div>
    </div>
  )
}

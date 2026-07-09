import type { BotFilterState } from '../../types'
import { useTranslation, Trans } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'
import { InheritOverrideControl, type InheritOverrideValue } from '../../../common/InheritOverrideControl'
import { BotFilterFields } from './BotFilterFields'

interface BotFilterSettingsProps {
  botFilterData: BotFilterState
  setBotFilterData: React.Dispatch<React.SetStateAction<BotFilterState>>
}

export function BotFilterSettings({ botFilterData, setBotFilterData }: BotFilterSettingsProps) {
  const { t } = useTranslation('proxyHost')

  // Tri-state derived from bot-filter state (mirrors GeoIPSettings):
  //   enabled=true         → override (host uses its own bot filter)
  //   disableGlobal=true   → disable  (host has no bot filter at all)
  //   otherwise            → inherit  (host uses the global default)
  const mode: InheritOverrideValue = botFilterData.enabled
    ? 'override'
    : botFilterData.disableGlobal
      ? 'disable'
      : 'inherit'

  const handleModeChange = (value: InheritOverrideValue) => {
    if (value === 'override') {
      setBotFilterData((prev) => ({ ...prev, enabled: true, disableGlobal: false }))
    } else if (value === 'disable') {
      setBotFilterData((prev) => ({ ...prev, enabled: false, disableGlobal: true }))
    } else {
      setBotFilterData((prev) => ({ ...prev, enabled: false, disableGlobal: false }))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
          {t('form.security.botFilter.title')}
          <HelpTip contentKey="help.security.botFilter" />
        </span>
      </div>

      <InheritOverrideControl value={mode} onChange={handleModeChange} />

      {mode === 'inherit' && (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.security.botFilter.inheritHint')}</p>
      )}
      {mode === 'disable' && (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.security.botFilter.disableHint')}</p>
      )}

      {mode === 'override' && (
        <div className="p-4 rounded-lg border-2 bg-orange-50 dark:bg-orange-900/10 border-orange-200 dark:border-orange-800 transition-colors space-y-3">
          {/* Settings link */}
          <p className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <Trans
              ns="proxyHost"
              i18nKey="form.security.botFilter.settingsLink"
              components={{ 1: <span className="font-medium text-primary-600" /> }}
            />
          </p>
          <BotFilterFields data={botFilterData} setData={setBotFilterData} />
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'
import { InheritOverrideControl, type InheritOverrideValue } from '../../../common/InheritOverrideControl'
import { CloudProviderFields } from './CloudProviderFields'

interface CloudProviderBlockingProps {
  blockedProviders: string[]
  setBlockedProviders: (providers: string[]) => void
  challengeMode: boolean
  setChallengeMode: (enabled: boolean) => void
  allowSearchBots: boolean
  setAllowSearchBots: (enabled: boolean) => void
  cloudDisableGlobal: boolean
  setCloudDisableGlobal: (disabled: boolean) => void
}

export function CloudProviderBlocking({
  blockedProviders,
  setBlockedProviders,
  challengeMode,
  setChallengeMode,
  allowSearchBots,
  setAllowSearchBots,
  cloudDisableGlobal,
  setCloudDisableGlobal,
}: CloudProviderBlockingProps) {
  const { t } = useTranslation('proxyHost')

  // Cloud blocking has no explicit enabled flag — it is "active" when the host
  // blocks any provider. The tri-state is therefore derived, with a local mode
  // to preserve an explicit "override" intent even before the user picks any
  // provider (an empty override otherwise reads back as inherit).
  const [mode, setMode] = useState<InheritOverrideValue>(
    blockedProviders.length > 0 ? 'override' : cloudDisableGlobal ? 'disable' : 'inherit',
  )

  useEffect(() => {
    if (blockedProviders.length > 0) setMode('override')
    else if (cloudDisableGlobal) setMode('disable')
    // Empty + not disabled: leave the current mode so an explicit "override"
    // intent survives until the user picks providers or switches away.
  }, [blockedProviders.length, cloudDisableGlobal])

  const handleModeChange = (value: InheritOverrideValue) => {
    setMode(value)
    if (value === 'override') {
      setCloudDisableGlobal(false)
    } else if (value === 'disable') {
      setBlockedProviders([])
      setChallengeMode(false)
      setAllowSearchBots(false)
      setCloudDisableGlobal(true)
    } else {
      setBlockedProviders([])
      setChallengeMode(false)
      setAllowSearchBots(false)
      setCloudDisableGlobal(false)
    }
  }

  return (
    <div className={`p-4 rounded-lg border-2 transition-colors ${mode === 'override' ? 'bg-blue-50 dark:bg-blue-900/10 border-blue-200 dark:border-blue-800' : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700'}`}>
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-10 h-10 rounded-full flex items-center justify-center ${mode === 'override' ? 'bg-blue-100 dark:bg-blue-900/30' : 'bg-slate-200 dark:bg-slate-700/50'}`}>
          <svg className={`w-5 h-5 ${mode === 'override' ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
          </svg>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
              {t('form.security.cloudProvider.title', 'Cloud Provider Blocking')}
              <HelpTip contentKey="help.security.cloudProvider" />
            </span>
            {blockedProviders.length > 0 && (
              <span className="px-1.5 py-0.5 text-xs font-medium rounded bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300">
                {blockedProviders.length} selected
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {t('form.security.cloudProvider.description', 'Block traffic from known cloud service providers')}
          </p>
        </div>
      </div>

      <InheritOverrideControl value={mode} onChange={handleModeChange} />

      {mode === 'inherit' && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('form.security.cloudProvider.inheritHint')}</p>
      )}
      {mode === 'disable' && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('form.security.cloudProvider.disableHint')}</p>
      )}

      {mode === 'override' && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-blue-200 dark:border-blue-800">
          <CloudProviderFields
            blockedProviders={blockedProviders}
            setBlockedProviders={setBlockedProviders}
            challengeMode={challengeMode}
            setChallengeMode={setChallengeMode}
            allowSearchBots={allowSearchBots}
            setAllowSearchBots={setAllowSearchBots}
          />
        </div>
      )}
    </div>
  )
}

import type { BotFilterState } from '../../types'
import { useTranslation, Trans } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'

interface BotFilterSettingsProps {
  botFilterData: BotFilterState
  setBotFilterData: React.Dispatch<React.SetStateAction<BotFilterState>>
}

export function BotFilterSettings({ botFilterData, setBotFilterData }: BotFilterSettingsProps) {
  const { t } = useTranslation('proxyHost')
  return (
    <div className={`p-4 rounded-lg border-2 transition-colors ${botFilterData.enabled ? 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'
      }`}>
      <label className="flex items-center justify-between cursor-pointer">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${botFilterData.enabled ? 'bg-orange-100 dark:bg-orange-900/40' : 'bg-slate-200 dark:bg-slate-700'
            }`}>
            <svg className={`w-5 h-5 ${botFilterData.enabled ? 'text-orange-600 dark:text-orange-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <div>
            <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
              {t('form.security.botFilter.title')}
              <HelpTip contentKey="help.security.botFilter" />
            </span>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.security.botFilter.description')}</p>
          </div>
        </div>
        <input
          type="checkbox"
          checked={botFilterData.enabled}
          onChange={(e) =>
            setBotFilterData((prev) => ({
              ...prev,
              enabled: e.target.checked,
            }))
          }
          className="rounded border-slate-300 dark:border-slate-600 text-orange-600 focus:ring-orange-500 h-5 w-5 dark:bg-slate-700"
        />
      </label>

      {botFilterData.enabled && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-orange-200 dark:border-orange-800 space-y-3">
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

          {/* Quick options - Row 1 */}
          <div className="grid grid-cols-2 gap-3">
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-orange-100/50 dark:hover:bg-orange-900/30 transition-colors">
              <input
                type="checkbox"
                checked={botFilterData.block_bad_bots}
                onChange={(e) =>
                  setBotFilterData((prev) => ({
                    ...prev,
                    block_bad_bots: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 dark:border-slate-600 text-red-600 focus:ring-red-500 dark:bg-slate-700"
              />
              <div>
                <span className="text-sm text-slate-700 dark:text-slate-300 font-medium">{t('form.security.botFilter.blockBadBots')}</span>
                <p className="text-xs text-slate-400 dark:text-slate-500">{t('form.security.botFilter.blockBadBotsDescription')}</p>
              </div>
            </label>
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-orange-100/50 dark:hover:bg-orange-900/30 transition-colors">
              <input
                type="checkbox"
                checked={botFilterData.block_ai_bots}
                onChange={(e) =>
                  setBotFilterData((prev) => ({
                    ...prev,
                    block_ai_bots: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 dark:border-slate-600 text-purple-600 focus:ring-purple-500 dark:bg-slate-700"
              />
              <div>
                <span className="text-sm text-slate-700 dark:text-slate-300 font-medium">{t('form.security.botFilter.blockAiBots')}</span>
                <p className="text-xs text-slate-400 dark:text-slate-500">{t('form.security.botFilter.blockAiBotsDescription')}</p>
              </div>
            </label>
          </div>

          {/* Quick options - Row 2 */}
          <div className="grid grid-cols-2 gap-3">
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-orange-100/50 dark:hover:bg-orange-900/30 transition-colors">
              <input
                type="checkbox"
                checked={botFilterData.allow_search_engines}
                onChange={(e) =>
                  setBotFilterData((prev) => ({
                    ...prev,
                    allow_search_engines: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 dark:border-slate-600 text-green-600 focus:ring-green-500 dark:bg-slate-700"
              />
              <div>
                <span className="text-sm text-slate-700 dark:text-slate-300 font-medium">{t('form.security.botFilter.allowSearchEngines')}</span>
                <p className="text-xs text-slate-400 dark:text-slate-500">{t('form.security.botFilter.allowSearchEnginesDescription')}</p>
              </div>
            </label>
            <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-orange-100/50 dark:hover:bg-orange-900/30 transition-colors">
              <input
                type="checkbox"
                checked={botFilterData.block_suspicious_clients ?? false}
                onChange={(e) =>
                  setBotFilterData((prev) => ({
                    ...prev,
                    block_suspicious_clients: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 dark:border-slate-600 text-orange-600 focus:ring-orange-500 dark:bg-slate-700"
              />
              <div>
                <span className="text-sm text-slate-700 dark:text-slate-300 font-medium">{t('form.security.botFilter.blockSuspicious')}</span>
                <p className="text-xs text-slate-400 dark:text-slate-500">{t('form.security.botFilter.blockSuspiciousDescription')}</p>
              </div>
            </label>
          </div>

          {/* Custom blocked agents */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('form.security.botFilter.customBlocked')}
            </label>
            <textarea
              value={botFilterData.custom_blocked_agents || ''}
              onChange={(e) =>
                setBotFilterData((prev) => ({
                  ...prev,
                  custom_blocked_agents: e.target.value,
                }))
              }
              placeholder={t('form.security.botFilter.customBlockedPlaceholder')}
              rows={3}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-orange-500 focus:border-orange-500 dark:bg-slate-700 dark:text-white"
            />
          </div>

          {/* Custom allowed agents */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('form.security.botFilter.customAllowed')}
            </label>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">
              {t('form.security.botFilter.customAllowedDescription')}
            </p>
            <textarea
              value={botFilterData.custom_allowed_agents || ''}
              onChange={(e) =>
                setBotFilterData((prev) => ({
                  ...prev,
                  custom_allowed_agents: e.target.value,
                }))
              }
              placeholder={t('form.security.botFilter.customAllowedPlaceholder')}
              rows={3}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-green-500 focus:border-green-500 dark:bg-slate-700 dark:text-white"
            />
          </div>
        </div>
      )}
    </div>
  )
}

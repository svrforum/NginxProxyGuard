import type { CreateBotFilterRequest } from '../../../../types/security'
import { useTranslation } from 'react-i18next'

/**
 * The bot-filter option fields (block toggles + custom agent lists), shared by
 * the per-host BotFilterSettings (override mode) and the GlobalBotFilterManager.
 * Feature-agnostic to the enable/inherit wrapper — the parent decides when to
 * render it. Generic over any state extending CreateBotFilterRequest so both
 * BotFilterState and the global manager's local state can drive it.
 */
interface BotFilterFieldsProps<T extends CreateBotFilterRequest> {
  data: T
  setData: React.Dispatch<React.SetStateAction<T>>
}

export function BotFilterFields<T extends CreateBotFilterRequest>({
  data,
  setData,
}: BotFilterFieldsProps<T>) {
  const { t } = useTranslation('proxyHost')

  return (
    <div className="space-y-3">
      {/* Quick options - Row 1 */}
      <div className="grid grid-cols-2 gap-3">
        <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-orange-100/50 dark:hover:bg-orange-900/30 transition-colors">
          <input
            type="checkbox"
            checked={data.block_bad_bots ?? false}
            onChange={(e) => setData((prev) => ({ ...prev, block_bad_bots: e.target.checked }))}
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
            checked={data.block_ai_bots ?? false}
            onChange={(e) => setData((prev) => ({ ...prev, block_ai_bots: e.target.checked }))}
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
            checked={data.allow_search_engines ?? false}
            onChange={(e) => setData((prev) => ({ ...prev, allow_search_engines: e.target.checked }))}
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
            checked={data.block_suspicious_clients ?? false}
            onChange={(e) => setData((prev) => ({ ...prev, block_suspicious_clients: e.target.checked }))}
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
          value={data.custom_blocked_agents || ''}
          onChange={(e) => setData((prev) => ({ ...prev, custom_blocked_agents: e.target.value }))}
          placeholder={t('form.security.botFilter.customBlockedPlaceholder')}
          rows={3}
          className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors dark:bg-slate-700 dark:text-white"
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
          value={data.custom_allowed_agents || ''}
          onChange={(e) => setData((prev) => ({ ...prev, custom_allowed_agents: e.target.value }))}
          placeholder={t('form.security.botFilter.customAllowedPlaceholder')}
          rows={3}
          className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors dark:bg-slate-700 dark:text-white"
        />
      </div>
    </div>
  )
}

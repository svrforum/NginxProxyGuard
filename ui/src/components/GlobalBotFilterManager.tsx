import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getGlobalBotFilter, updateGlobalBotFilter, type GlobalBotFilter } from '../api/global-bot-filter'
import { BotFilterFields } from './proxy-host/tabs/security/BotFilterFields'

type BotFilterDraft = Omit<GlobalBotFilter, 'id' | 'created_at' | 'updated_at'>

const EMPTY: BotFilterDraft = {
  enabled: false,
  block_bad_bots: true,
  block_ai_bots: false,
  allow_search_engines: true,
  block_suspicious_clients: false,
  custom_blocked_agents: '',
  custom_allowed_agents: '',
  challenge_suspicious: false,
}

function hydrate(g: GlobalBotFilter): BotFilterDraft {
  return {
    enabled: g.enabled,
    block_bad_bots: g.block_bad_bots,
    block_ai_bots: g.block_ai_bots,
    allow_search_engines: g.allow_search_engines,
    block_suspicious_clients: g.block_suspicious_clients,
    custom_blocked_agents: g.custom_blocked_agents || '',
    custom_allowed_agents: g.custom_allowed_agents || '',
    challenge_suspicious: g.challenge_suspicious,
  }
}

export function GlobalBotFilterManager() {
  const { t } = useTranslation('waf')
  const queryClient = useQueryClient()

  const [data, setData] = useState<BotFilterDraft>(EMPTY)
  const [dirty, setDirty] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  const { data: global, isLoading } = useQuery({
    queryKey: ['global-bot-filter'],
    queryFn: getGlobalBotFilter,
    refetchInterval: 60000,
  })

  useEffect(() => {
    if (global) {
      setData(hydrate(global))
      setDirty(false)
    }
  }, [global])

  const setDataDirty: React.Dispatch<React.SetStateAction<BotFilterDraft>> = (action) => {
    setData(action)
    setDirty(true)
  }

  const mutation = useMutation({
    mutationFn: () => updateGlobalBotFilter(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-bot-filter'] })
      setDirty(false)
      setSaveMessage({ type: 'success', message: t('globalBotFilter.saveSuccess') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
    onError: () => {
      setSaveMessage({ type: 'error', message: t('globalBotFilter.saveFailed') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
  })

  const handleDiscard = () => {
    setData(global ? hydrate(global) : EMPTY)
    setDirty(false)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
          {t('globalBotFilter.title')}
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('globalBotFilter.subtitle')}
        </p>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`p-4 rounded-lg flex items-center gap-3 ${
          saveMessage.type === 'success'
            ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-800 dark:text-green-300'
            : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-300'
        }`}>
          <span>{saveMessage.message}</span>
        </div>
      )}

      {/* Pending Changes Banner */}
      {dirty && (
        <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg flex items-center justify-between">
          <div className="flex items-center gap-3 text-amber-800 dark:text-amber-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="font-medium">{t('globalBotFilter.unsavedChanges')}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleDiscard}
              className="px-3 py-1.5 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded transition-colors"
            >
              {t('common:buttons.discard')}
            </button>
            <button
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
              className="px-4 py-1.5 text-sm bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded font-medium transition-colors flex items-center gap-2"
            >
              {mutation.isPending && (
                <svg className="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" strokeDasharray="50 20" />
                </svg>
              )}
              {t('common:buttons.save')}
            </button>
          </div>
        </div>
      )}

      {/* Enable Toggle Card */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              {t('globalBotFilter.enableTitle')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {t('globalBotFilter.enableDescription')}
            </p>
          </div>
          <button
            onClick={() => setDataDirty((prev) => ({ ...prev, enabled: !prev.enabled }))}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              data.enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
              data.enabled ? 'translate-x-6' : 'translate-x-1'
            }`} />
          </button>
        </div>

        {data.enabled && (
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <BotFilterFields data={data} setData={setDataDirty} />
          </div>
        )}
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm text-blue-800 dark:text-blue-300">
            <p className="font-medium">{t('globalBotFilter.infoTitle')}</p>
            <p className="mt-1">{t('globalBotFilter.infoDesc')}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

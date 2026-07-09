import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getGlobalCloudProviders, updateGlobalCloudProviders } from '../api/global-cloud-providers'
import { CloudProviderFields } from './proxy-host/tabs/security/CloudProviderFields'

export function GlobalCloudProviderManager() {
  const { t } = useTranslation('waf')
  const queryClient = useQueryClient()

  const [blockedProviders, setBlockedProviders] = useState<string[]>([])
  const [challengeMode, setChallengeMode] = useState(false)
  const [allowSearchBots, setAllowSearchBots] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  const { data: global, isLoading } = useQuery({
    queryKey: ['global-cloud-providers'],
    queryFn: getGlobalCloudProviders,
    refetchInterval: 60000,
  })

  useEffect(() => {
    if (global) {
      setBlockedProviders(global.blocked_providers || [])
      setChallengeMode(global.challenge_mode)
      setAllowSearchBots(global.allow_search_bots)
      setDirty(false)
    }
  }, [global])

  const wrap = <T,>(setter: (v: T) => void) => (v: T) => { setter(v); setDirty(true) }

  const mutation = useMutation({
    mutationFn: () => updateGlobalCloudProviders({
      blocked_providers: blockedProviders,
      challenge_mode: challengeMode,
      allow_search_bots: allowSearchBots,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-cloud-providers'] })
      setDirty(false)
      setSaveMessage({ type: 'success', message: t('globalCloudProviders.saveSuccess') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
    onError: () => {
      setSaveMessage({ type: 'error', message: t('globalCloudProviders.saveFailed') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
  })

  const handleDiscard = () => {
    setBlockedProviders(global?.blocked_providers || [])
    setChallengeMode(global?.challenge_mode || false)
    setAllowSearchBots(global?.allow_search_bots || false)
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
          {t('globalCloudProviders.title')}
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('globalCloudProviders.subtitle')}
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
            <span className="font-medium">{t('globalCloudProviders.unsavedChanges')}</span>
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

      {/* Provider selection card */}
      <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
        <CloudProviderFields
          blockedProviders={blockedProviders}
          setBlockedProviders={wrap(setBlockedProviders)}
          challengeMode={challengeMode}
          setChallengeMode={wrap(setChallengeMode)}
          allowSearchBots={allowSearchBots}
          setAllowSearchBots={wrap(setAllowSearchBots)}
        />
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm text-blue-800 dark:text-blue-300">
            <p className="font-medium">{t('globalCloudProviders.infoTitle')}</p>
            <p className="mt-1">{t('globalCloudProviders.infoDesc')}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

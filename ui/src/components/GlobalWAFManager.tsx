import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getGlobalWAF, updateGlobalWAF, type GlobalWAF } from '../api/global-waf'
import { WAFFields } from './proxy-host/tabs/security/WAFFields'

type Draft = {
  enabled: boolean
  mode: string
  paranoia_level: number
  anomaly_threshold: number
}

const EMPTY: Draft = { enabled: false, mode: 'detection', paranoia_level: 1, anomaly_threshold: 5 }

function hydrate(g: GlobalWAF): Draft {
  return {
    enabled: g.enabled,
    mode: g.mode || 'detection',
    paranoia_level: g.paranoia_level || 1,
    anomaly_threshold: g.anomaly_threshold || 5,
  }
}

export function GlobalWAFManager() {
  const { t } = useTranslation('waf')
  const queryClient = useQueryClient()

  const [data, setData] = useState<Draft>(EMPTY)
  const [dirty, setDirty] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  const { data: global, isLoading } = useQuery({
    queryKey: ['global-waf'],
    queryFn: getGlobalWAF,
    refetchInterval: 60000,
  })

  useEffect(() => {
    if (global) {
      setData(hydrate(global))
      setDirty(false)
    }
  }, [global])

  const patch = (p: Partial<Draft>) => {
    setData((prev) => ({ ...prev, ...p }))
    setDirty(true)
  }

  const mutation = useMutation({
    mutationFn: () => updateGlobalWAF(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-waf'] })
      setDirty(false)
      setSaveMessage({ type: 'success', message: t('globalWAF.saveSuccess') })
      setTimeout(() => setSaveMessage(null), 6000)
    },
    onError: () => {
      setSaveMessage({ type: 'error', message: t('globalWAF.saveFailed') })
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
          {t('globalWAF.title')}
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('globalWAF.subtitle')}
        </p>
      </div>

      {/* Restart caveat — WAF/ModSec changes only apply after a proxy restart */}
      <div className="p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <p className="text-sm text-amber-800 dark:text-amber-300">{t('globalWAF.restartNote')}</p>
        </div>
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
            <span className="font-medium">{t('globalWAF.unsavedChanges')}</span>
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
              {t('globalWAF.enableTitle')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {t('globalWAF.enableDescription')}
            </p>
          </div>
          <button
            onClick={() => patch({ enabled: !data.enabled })}
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
            <WAFFields
              values={{
                waf_mode: data.mode,
                waf_paranoia_level: data.paranoia_level,
                waf_anomaly_threshold: data.anomaly_threshold,
              }}
              onChange={(p) => patch({
                mode: p.waf_mode ?? data.mode,
                paranoia_level: p.waf_paranoia_level ?? data.paranoia_level,
                anomaly_threshold: p.waf_anomaly_threshold ?? data.anomaly_threshold,
              })}
            />
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
            <p className="font-medium">{t('globalWAF.infoTitle')}</p>
            <p className="mt-1">{t('globalWAF.infoDesc')}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

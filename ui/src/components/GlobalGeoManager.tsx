import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getGlobalGeo, updateGlobalGeo } from '../api/global-geo'
import { getCountryCodes } from '../api/access'
import { getGeoIPStatus } from '../api/settings'
import type { GeoDataState } from './proxy-host/types'
import { GeoRestrictionFields } from './proxy-host/tabs/security/GeoRestrictionFields'
import { PriorityAllowIPs } from './proxy-host/tabs/security/PriorityAllowIPs'

const EMPTY_GEO: GeoDataState = {
  enabled: false,
  mode: 'blacklist',
  countries: [],
  allowed_ips: [],
  allow_private_ips: true,
  allow_search_bots: false,
  challenge_mode: false,
}

export function GlobalGeoManager() {
  const { t } = useTranslation('waf')
  const queryClient = useQueryClient()

  const [geoData, setGeoData] = useState<GeoDataState>(EMPTY_GEO)
  const [allowedIPsInput, setAllowedIPsInput] = useState('')
  const [geoSearchTerm, setGeoSearchTerm] = useState('')
  const [dirty, setDirty] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  const { data: global, isLoading } = useQuery({
    queryKey: ['global-geo'],
    queryFn: getGlobalGeo,
    refetchInterval: 60000,
  })

  const { data: geoipStatus } = useQuery({
    queryKey: ['geoipStatus'],
    queryFn: getGeoIPStatus,
  })

  const isGeoIPAvailable =
    geoipStatus?.status === 'active' || (geoipStatus?.enabled && geoipStatus?.country_db)

  const { data: countryCodes } = useQuery({
    queryKey: ['countryCodes'],
    queryFn: getCountryCodes,
    enabled: !!isGeoIPAvailable,
  })

  // Hydrate local state whenever the server record loads/refetches.
  useEffect(() => {
    if (global) {
      setGeoData({
        enabled: global.enabled,
        mode: global.mode,
        countries: global.countries || [],
        allowed_ips: global.allowed_ips || [],
        allow_private_ips: global.allow_private_ips ?? true,
        allow_search_bots: global.allow_search_bots ?? false,
        challenge_mode: global.challenge_mode ?? false,
      })
      setAllowedIPsInput((global.allowed_ips || []).join('\n'))
      setDirty(false)
    }
  }, [global])

  // Wrapped setters so any edit flips the dirty flag (reveals the save banner).
  const setGeoDataDirty: React.Dispatch<React.SetStateAction<GeoDataState>> = (action) => {
    setGeoData(action)
    setDirty(true)
  }
  const setAllowedIPsInputDirty = (value: string) => {
    setAllowedIPsInput(value)
    setDirty(true)
  }

  const mutation = useMutation({
    mutationFn: () =>
      updateGlobalGeo({
        enabled: geoData.enabled,
        mode: geoData.mode,
        countries: geoData.countries,
        allowed_ips: geoData.allowed_ips,
        allow_private_ips: geoData.allow_private_ips,
        allow_search_bots: geoData.allow_search_bots,
        challenge_mode: geoData.challenge_mode,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-geo'] })
      setDirty(false)
      setSaveMessage({ type: 'success', message: t('globalGeo.saveSuccess') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
    onError: () => {
      setSaveMessage({ type: 'error', message: t('globalGeo.saveFailed') })
      setTimeout(() => setSaveMessage(null), 5000)
    },
  })

  const handleDiscard = () => {
    if (global) {
      setGeoData({
        enabled: global.enabled,
        mode: global.mode,
        countries: global.countries || [],
        allowed_ips: global.allowed_ips || [],
        allow_private_ips: global.allow_private_ips ?? true,
        allow_search_bots: global.allow_search_bots ?? false,
        challenge_mode: global.challenge_mode ?? false,
      })
      setAllowedIPsInput((global.allowed_ips || []).join('\n'))
    } else {
      setGeoData(EMPTY_GEO)
      setAllowedIPsInput('')
    }
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
          {t('globalGeo.title')}
        </h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
          {t('globalGeo.subtitle')}
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
            <span className="font-medium">{t('globalGeo.unsavedChanges')}</span>
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

      {!isGeoIPAvailable ? (
        <div className="p-4 rounded-lg border-2 border-dashed border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 transition-colors">
          <div className="flex items-center gap-3 text-slate-500 dark:text-slate-400">
            <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <span className="block text-sm font-medium text-slate-700 dark:text-slate-300">{t('globalGeo.notAvailable')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('globalGeo.notAvailableDescription')}</p>
            </div>
          </div>
        </div>
      ) : (
        <>
          {/* Enable Toggle Card */}
          <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                  {t('globalGeo.enableTitle')}
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  {t('globalGeo.enableDescription')}
                </p>
              </div>
              <button
                onClick={() => setGeoDataDirty((prev) => ({ ...prev, enabled: !prev.enabled }))}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  geoData.enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
                }`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
                  geoData.enabled ? 'translate-x-6' : 'translate-x-1'
                }`} />
              </button>
            </div>

            {geoData.enabled && (
              <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
                <GeoRestrictionFields
                  geoData={geoData}
                  setGeoData={setGeoDataDirty}
                  geoSearchTerm={geoSearchTerm}
                  setGeoSearchTerm={setGeoSearchTerm}
                  countryCodes={countryCodes}
                />
              </div>
            )}
          </div>

          {/* Priority Allow IPs (bypass the global restriction) */}
          {geoData.enabled && (
            <PriorityAllowIPs
              allowedIPsInput={allowedIPsInput}
              setAllowedIPsInput={setAllowedIPsInputDirty}
              geoData={geoData}
              setGeoData={setGeoDataDirty}
            />
          )}
        </>
      )}

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div className="text-sm text-blue-800 dark:text-blue-300">
            <p className="font-medium">{t('globalGeo.infoTitle')}</p>
            <p className="mt-1">{t('globalGeo.infoDesc')}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

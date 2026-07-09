import type { GeoDataState } from '../../types'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'
import { InheritOverrideControl, type InheritOverrideValue } from '../../../common/InheritOverrideControl'
import { GeoRestrictionFields } from './GeoRestrictionFields'

interface GeoIPSettingsProps {
  geoData: GeoDataState
  setGeoData: React.Dispatch<React.SetStateAction<GeoDataState>>
  geoSearchTerm: string
  setGeoSearchTerm: (value: string) => void
  geoipStatus: { status: string; enabled?: boolean; country_db?: boolean } | undefined
  countryCodes: Record<string, string> | undefined
}

export function GeoIPSettings({
  geoData,
  setGeoData,
  geoSearchTerm,
  setGeoSearchTerm,
  geoipStatus,
  countryCodes,
}: GeoIPSettingsProps) {
  const { t } = useTranslation('proxyHost')
  // GeoIP is available if enabled=true and country_db exists, or if status is 'active'
  const isGeoIPAvailable = geoipStatus?.status === 'active' || (geoipStatus?.enabled && geoipStatus?.country_db)

  if (!isGeoIPAvailable) {
    return (
      <div className="p-4 rounded-lg border-2 border-dashed border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 transition-colors">
        <div className="flex items-center gap-3 text-slate-500 dark:text-slate-400">
          <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <span className="block text-sm font-medium text-slate-700 dark:text-slate-300">{t('form.security.geoip.notAvailable')}</span>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {t('form.security.geoip.notAvailableDescription')}
            </p>
          </div>
        </div>
      </div>
    )
  }

  // Tri-state derived from geo state:
  //   enabled=true         → override (host uses its own geo config)
  //   disableGlobal=true   → disable  (host has no geo at all)
  //   otherwise            → inherit  (host uses the global default)
  const mode: InheritOverrideValue = geoData.enabled
    ? 'override'
    : geoData.disableGlobal
      ? 'disable'
      : 'inherit'

  const handleModeChange = (value: InheritOverrideValue) => {
    if (value === 'override') {
      setGeoData((prev) => ({ ...prev, enabled: true, disableGlobal: false }))
    } else if (value === 'disable') {
      setGeoData((prev) => ({ ...prev, enabled: false, disableGlobal: true }))
    } else {
      setGeoData((prev) => ({ ...prev, enabled: false, disableGlobal: false }))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
          {t('form.security.geoip.title')}
          <HelpTip contentKey="help.security.geoip" />
        </span>
        {mode === 'override' && geoData.countries.length > 0 && (
          <span className={`px-1.5 py-0.5 text-xs font-medium rounded ${geoData.mode === 'whitelist' ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300' : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
            }`}>
            {geoData.mode === 'whitelist' ? t('form.security.geoip.modeAllow') : t('form.security.geoip.modeBlock')} {geoData.countries.length}
          </span>
        )}
      </div>

      <InheritOverrideControl value={mode} onChange={handleModeChange} />

      {mode === 'inherit' && (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.security.geoip.inheritHint')}</p>
      )}
      {mode === 'disable' && (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.security.geoip.disableHint')}</p>
      )}

      {mode === 'override' && (
        <div className="p-4 rounded-lg border-2 bg-emerald-50 dark:bg-emerald-900/10 border-emerald-200 dark:border-emerald-800 transition-colors">
          <GeoRestrictionFields
            geoData={geoData}
            setGeoData={setGeoData}
            geoSearchTerm={geoSearchTerm}
            setGeoSearchTerm={setGeoSearchTerm}
            countryCodes={countryCodes}
          />
        </div>
      )}
    </div>
  )
}

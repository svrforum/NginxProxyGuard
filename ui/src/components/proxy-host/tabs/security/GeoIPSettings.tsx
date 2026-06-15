import type { GeoDataState } from '../../types'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'

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

  return (
    <>
      {/* GeoIP Restriction */}
      <div className={`p-4 rounded-lg border-2 transition-colors ${geoData.enabled ? 'bg-emerald-50 dark:bg-emerald-900/10 border-emerald-200 dark:border-emerald-800' : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700'
        }`}>
        <label className="flex items-center justify-between cursor-pointer">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center ${geoData.enabled ? 'bg-emerald-100 dark:bg-emerald-900/30' : 'bg-slate-200 dark:bg-slate-700'
              }`}>
              <svg className={`w-5 h-5 ${geoData.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                  {t('form.security.geoip.title')}
                  <HelpTip contentKey="help.security.geoip" />
                </span>
                {geoData.enabled && geoData.countries.length > 0 && (
                  <span className={`px-1.5 py-0.5 text-xs font-medium rounded ${geoData.mode === 'whitelist' ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300' : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                    }`}>
                    {geoData.mode === 'whitelist' ? t('form.security.geoip.modeAllow') : t('form.security.geoip.modeBlock')} {geoData.countries.length}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.security.geoip.description')}</p>
            </div>
          </div>
          <input
            type="checkbox"
            checked={geoData.enabled}
            onChange={(e) =>
              setGeoData((prev) => ({
                ...prev,
                enabled: e.target.checked,
              }))
            }
            className="rounded border-slate-300 dark:border-slate-600 text-emerald-600 focus:ring-emerald-500 h-5 w-5 bg-white dark:bg-slate-700"
          />
        </label>

        {geoData.enabled && (
          <div className="mt-4 ml-13 pl-4 border-l-2 border-emerald-200 dark:border-emerald-800 space-y-4">
            {/* Mode Selection */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{t('form.security.geoip.mode')}</label>
              <div className="flex gap-3">
                <label className={`flex-1 p-3 rounded-lg border cursor-pointer transition-colors ${geoData.mode === 'blacklist' ? 'bg-red-100 dark:bg-red-900/30 border-red-300 dark:border-red-700' : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50'
                  }`}>
                  <input
                    type="radio"
                    name="geo_mode"
                    value="blacklist"
                    checked={geoData.mode === 'blacklist'}
                    onChange={() => setGeoData(prev => ({ ...prev, mode: 'blacklist' }))}
                    className="sr-only"
                  />
                  <div className="text-center">
                    <span className={`block text-sm font-medium ${geoData.mode === 'blacklist' ? 'text-red-900 dark:text-red-300' : 'text-slate-900 dark:text-white'}`}>{t('form.security.geoip.modeBlock')}</span>
                    <span className={`block text-xs ${geoData.mode === 'blacklist' ? 'text-red-700 dark:text-red-400' : 'text-slate-500 dark:text-slate-400'}`}>{t('form.security.geoip.modeBlockDescription')}</span>
                  </div>
                </label>
                <label className={`flex-1 p-3 rounded-lg border cursor-pointer transition-colors ${geoData.mode === 'whitelist' ? 'bg-green-100 dark:bg-green-900/30 border-green-300 dark:border-green-700' : 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50'
                  }`}>
                  <input
                    type="radio"
                    name="geo_mode"
                    value="whitelist"
                    checked={geoData.mode === 'whitelist'}
                    onChange={() => setGeoData(prev => ({ ...prev, mode: 'whitelist' }))}
                    className="sr-only"
                  />
                  <div className="text-center">
                    <span className={`block text-sm font-medium ${geoData.mode === 'whitelist' ? 'text-green-900 dark:text-green-300' : 'text-slate-900 dark:text-white'}`}>{t('form.security.geoip.modeAllow')}</span>
                    <span className={`block text-xs ${geoData.mode === 'whitelist' ? 'text-green-700 dark:text-green-400' : 'text-slate-500 dark:text-slate-400'}`}>{t('form.security.geoip.modeAllowDescription')}</span>
                  </div>
                </label>
              </div>
            </div>

            {/* Challenge Mode */}
            <label className="flex items-center gap-2 cursor-pointer py-2 px-3 bg-blue-50 dark:bg-blue-900/10 rounded-lg border border-blue-200 dark:border-blue-800 transition-colors">
              <input
                type="checkbox"
                checked={geoData.challenge_mode}
                onChange={(e) =>
                  setGeoData((prev) => ({
                    ...prev,
                    challenge_mode: e.target.checked,
                  }))
                }
                className="rounded border-blue-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700"
              />
              <div>
                <span className="text-sm font-medium text-blue-800 dark:text-blue-300">{t('form.security.geoip.challengeMode')}</span>
                <p className="text-xs text-blue-600 dark:text-blue-400">{t('form.security.geoip.challengeModeDescription')}</p>
              </div>
            </label>

            {/* Allow Private IPs */}
            <label className="flex items-center gap-2 cursor-pointer py-2 px-3 bg-amber-50 dark:bg-amber-900/10 rounded-lg border border-amber-200 dark:border-amber-800 transition-colors">
              <input
                type="checkbox"
                checked={geoData.allow_private_ips ?? true}
                onChange={(e) =>
                  setGeoData((prev) => ({
                    ...prev,
                    allow_private_ips: e.target.checked,
                  }))
                }
                className="rounded border-amber-300 dark:border-slate-600 text-amber-600 focus:ring-amber-500 bg-white dark:bg-slate-700"
              />
              <div>
                <span className="text-sm font-medium text-amber-800 dark:text-amber-300">{t('form.security.geoip.allowPrivateIPs')}</span>
                <p className="text-xs text-amber-600 dark:text-amber-400">{t('form.security.geoip.allowPrivateIPsDescription')}</p>
              </div>
            </label>

            {/* Allow Search Bots */}
            <label className="flex items-center gap-2 cursor-pointer py-2 px-3 bg-purple-50 dark:bg-purple-900/10 rounded-lg border border-purple-200 dark:border-purple-800 transition-colors">
              <input
                type="checkbox"
                checked={geoData.allow_search_bots ?? false}
                onChange={(e) =>
                  setGeoData((prev) => ({
                    ...prev,
                    allow_search_bots: e.target.checked,
                  }))
                }
                className="rounded border-purple-300 dark:border-slate-600 text-purple-600 focus:ring-purple-500 bg-white dark:bg-slate-700"
              />
              <div>
                <span className="text-sm font-medium text-purple-800 dark:text-purple-300">{t('form.security.geoip.allowSearchBots')}</span>
                <p className="text-xs text-purple-600 dark:text-purple-400">{t('form.security.geoip.allowSearchBotsDescription')}</p>
              </div>
            </label>

            {/* Country Search & Quick Actions */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                  {t('form.security.geoip.searchCountries')}
                </label>
                <div className="flex gap-1">
                  <button
                    type="button"
                    onClick={() => {
                      if (countryCodes) {
                        const filtered = Object.keys(countryCodes).filter(
                          (code) =>
                            code.toLowerCase().includes(geoSearchTerm.toLowerCase()) ||
                            countryCodes[code].toLowerCase().includes(geoSearchTerm.toLowerCase())
                        )
                        setGeoData((prev) => ({
                          ...prev,
                          countries: [...new Set([...prev.countries, ...filtered])],
                        }))
                      }
                    }}
                    className="px-2 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300 bg-emerald-100 dark:bg-emerald-900/30 hover:bg-emerald-200 dark:hover:bg-emerald-900/50 rounded transition-colors"
                  >
                    {geoSearchTerm ? t('form.security.geoip.selectFiltered') : t('common:buttons.selectAll')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setGeoData((prev) => ({ ...prev, countries: [] }))}
                    className="px-2 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded transition-colors"
                  >
                    {t('form.security.geoip.clearAll')}
                  </button>
                </div>
              </div>
              <input
                type="text"
                value={geoSearchTerm}
                onChange={(e) => setGeoSearchTerm(e.target.value)}
                placeholder="Search by name or code..."
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400"
              />

              {/* Quick Presets */}
              <div className="flex flex-wrap gap-1 pt-1">
                <span className="text-xs text-slate-500 dark:text-slate-400 mr-1">{t('form.security.geoip.quickAdd')}:</span>
                <button
                  type="button"
                  onClick={() => setGeoData((prev) => ({
                    ...prev,
                    countries: [...new Set([...prev.countries, 'KR'])],
                  }))}
                  className="px-2 py-0.5 text-xs font-medium text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/20 hover:bg-indigo-100 dark:hover:bg-indigo-900/40 rounded transition-colors"
                >
                  + {t('form.security.geoip.korea')}
                </button>
                <button
                  type="button"
                  onClick={() => setGeoData((prev) => ({
                    ...prev,
                    countries: [...new Set([...prev.countries, 'CN', 'RU', 'KP', 'IR'])],
                  }))}
                  className="px-2 py-0.5 text-xs font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 rounded transition-colors"
                >
                  + {t('form.security.geoip.highRisk')}
                </button>
                <button
                  type="button"
                  onClick={() => setGeoData((prev) => ({
                    ...prev,
                    countries: [...new Set([...prev.countries, 'US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU', 'KR'])],
                  }))}
                  className="px-2 py-0.5 text-xs font-medium text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 hover:bg-green-100 dark:hover:bg-green-900/40 rounded transition-colors"
                >
                  + {t('form.security.geoip.majorMarkets')}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const eu = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE']
                    setGeoData((prev) => ({
                      ...prev,
                      countries: [...new Set([...prev.countries, ...eu])],
                    }))
                  }}
                  className="px-2 py-0.5 text-xs font-medium text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 rounded transition-colors"
                >
                  + {t('form.security.geoip.euCountries')}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const asia = ['CN', 'JP', 'KR', 'TW', 'HK', 'SG', 'TH', 'VN', 'MY', 'ID', 'PH', 'IN']
                    setGeoData((prev) => ({
                      ...prev,
                      countries: [...new Set([...prev.countries, ...asia])],
                    }))
                  }}
                  className="px-2 py-0.5 text-xs font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 hover:bg-amber-100 dark:hover:bg-amber-900/40 rounded transition-colors"
                >
                  + {t('form.security.geoip.asiaPacific')}
                </button>
              </div>
            </div>

            {/* Selected Countries */}
            {geoData.countries.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('form.security.geoip.selectedCountries')} ({geoData.countries.length})
                </label>
                <div className="flex flex-wrap gap-1">
                  {geoData.countries.map((code) => (
                    <button
                      key={code}
                      type="button"
                      onClick={() =>
                        setGeoData((prev) => ({
                          ...prev,
                          countries: prev.countries.filter((c) => c !== code),
                        }))
                      }
                      className={`px-2 py-1 text-xs rounded font-medium transition-colors ${geoData.mode === 'whitelist'
                        ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 hover:bg-green-200 dark:hover:bg-green-900/50'
                        : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 hover:bg-red-200 dark:hover:bg-red-900/50'
                        }`}
                    >
                      {code} {countryCodes?.[code] ? `- ${countryCodes[code]}` : ''} ×
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Country List */}
            <div className="max-h-48 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg p-2 bg-white dark:bg-slate-800 transition-colors">
              <div className="grid grid-cols-2 gap-1">
                {countryCodes &&
                  Object.entries(countryCodes)
                    .filter(([code, name]) =>
                      code.toLowerCase().includes(geoSearchTerm.toLowerCase()) ||
                      name.toLowerCase().includes(geoSearchTerm.toLowerCase())
                    )
                    .slice(0, 50)
                    .map(([code, name]) => (
                      <label
                        key={code}
                        className={`flex items-center gap-2 p-1.5 rounded cursor-pointer text-sm ${geoData.countries.includes(code)
                          ? geoData.mode === 'whitelist'
                            ? 'bg-green-50 dark:bg-green-900/20'
                            : 'bg-red-50 dark:bg-red-900/20'
                          : 'hover:bg-slate-50 dark:hover:bg-slate-700/50'
                          }`}
                      >
                        <input
                          type="checkbox"
                          checked={geoData.countries.includes(code)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setGeoData((prev) => ({
                                ...prev,
                                countries: [...prev.countries, code],
                              }))
                            } else {
                              setGeoData((prev) => ({
                                ...prev,
                                countries: prev.countries.filter((c) => c !== code),
                              }))
                            }
                          }}
                          className={`rounded border-slate-300 dark:border-slate-600 ${geoData.mode === 'whitelist'
                            ? 'text-green-600 focus:ring-green-500'
                            : 'text-red-600 focus:ring-red-500'
                            } bg-white dark:bg-slate-700`}
                        />
                        <span className="truncate text-slate-700 dark:text-slate-300">{code} - {name}</span>
                      </label>
                    ))}
              </div>
              {geoSearchTerm && countryCodes && Object.keys(countryCodes).filter(
                (code) =>
                  code.toLowerCase().includes(geoSearchTerm.toLowerCase()) ||
                  countryCodes[code].toLowerCase().includes(geoSearchTerm.toLowerCase())
              ).length === 0 && (
                  <p className="text-sm text-slate-500 dark:text-slate-400 text-center py-4">{t('form.security.geoip.noCountries')}</p>
                )}
            </div>
          </div>
        )}
      </div>
    </>
  )
}

import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'
import { api } from '../../../../api/client'

interface CloudProviderSummary {
  slug: string
  name: string
  region: string
  description?: string
  ip_count: number
  enabled: boolean
}

interface CloudProvidersByRegion {
  us: CloudProviderSummary[]
  eu: CloudProviderSummary[]
  cn: CloudProviderSummary[]
  kr: CloudProviderSummary[]
}

interface CloudProviderFieldsProps {
  blockedProviders: string[]
  setBlockedProviders: (providers: string[]) => void
  challengeMode: boolean
  setChallengeMode: (enabled: boolean) => void
  allowSearchBots: boolean
  setAllowSearchBots: (enabled: boolean) => void
}

const REGION_FLAGS: Record<string, string> = {
  us: '🇺🇸',
  eu: '🇪🇺',
  cn: '🇨🇳',
  kr: '🇰🇷',
}

const QUICK_PRESETS = {
  majorClouds: ['aws', 'gcp', 'azure', 'oracle', 'alibaba'],
  budgetVps: ['digitalocean', 'linode', 'vultr', 'hetzner', 'contabo', 'ovh'],
  asiaProviders: ['alibaba', 'tencent', 'huawei', 'naver', 'kt', 'smileserv'],
}

/**
 * The cloud-provider blocking fields (challenge mode, allow search bots, and the
 * regioned provider selector), shared by the per-host CloudProviderBlocking
 * (override mode) and the GlobalCloudProviderManager. The enable/inherit wrapper
 * is the parent's responsibility.
 */
export function CloudProviderFields({
  blockedProviders,
  setBlockedProviders,
  challengeMode,
  setChallengeMode,
  allowSearchBots,
  setAllowSearchBots,
}: CloudProviderFieldsProps) {
  const { t } = useTranslation('proxyHost')

  const { data: providers, isLoading } = useQuery({
    queryKey: ['cloud-providers-by-region'],
    queryFn: async () => api.get<CloudProvidersByRegion>('/api/v1/cloud-providers/by-region'),
  })

  const toggleProvider = (slug: string) => {
    if (blockedProviders.includes(slug)) {
      setBlockedProviders(blockedProviders.filter((s) => s !== slug))
    } else {
      setBlockedProviders([...blockedProviders, slug])
    }
  }

  const toggleAllInRegion = (region: keyof CloudProvidersByRegion) => {
    if (!providers) return
    const regionSlugs = providers[region].map((p) => p.slug)
    const allSelected = regionSlugs.every((slug) => blockedProviders.includes(slug))
    if (allSelected) {
      setBlockedProviders(blockedProviders.filter((s) => !regionSlugs.includes(s)))
    } else {
      setBlockedProviders([...new Set([...blockedProviders, ...regionSlugs])])
    }
  }

  const clearAll = () => setBlockedProviders([])

  const selectAll = () => {
    if (!providers) return
    setBlockedProviders([
      ...providers.us.map((p) => p.slug),
      ...providers.eu.map((p) => p.slug),
      ...providers.cn.map((p) => p.slug),
      ...providers.kr.map((p) => p.slug),
    ])
  }

  const applyPreset = (slugs: string[]) => setBlockedProviders([...new Set([...blockedProviders, ...slugs])])

  if (isLoading) {
    return (
      <div className="flex items-center gap-3 text-slate-500 py-4">
        <div className="w-6 h-6 border-2 border-slate-300 border-t-slate-600 rounded-full animate-spin" />
        <span className="text-sm">{t('common:loading')}</span>
      </div>
    )
  }

  if (!providers || (providers.us.length === 0 && providers.eu.length === 0 && providers.cn.length === 0 && providers.kr.length === 0)) {
    return null
  }

  return (
    <div className="space-y-4">
      {/* Challenge Mode */}
      <label className="flex items-center gap-2 cursor-pointer py-2 px-3 bg-blue-50 dark:bg-blue-900/10 rounded-lg border border-blue-200 dark:border-blue-800">
        <input
          type="checkbox"
          checked={challengeMode}
          onChange={(e) => setChallengeMode(e.target.checked)}
          className="rounded border-blue-300 dark:border-blue-700 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700 focus:ring-offset-0 dark:focus:ring-offset-slate-800"
        />
        <div>
          <span className="text-sm font-medium text-blue-800 dark:text-blue-300 flex items-center gap-2">
            {t('form.security.cloudProvider.challengeMode', 'Challenge Mode')}
            <HelpTip contentKey="help.security.cloudProviderChallenge" />
          </span>
          <p className="text-xs text-blue-600 dark:text-blue-400">
            {t('form.security.cloudProvider.challengeModeDescription', 'Show CAPTCHA verification instead of blocking')}
          </p>
        </div>
      </label>

      {/* Allow Search Bots */}
      <label className="flex items-center gap-2 cursor-pointer py-2 px-3 bg-green-50 dark:bg-green-900/10 rounded-lg border border-green-200 dark:border-green-800">
        <input
          type="checkbox"
          checked={allowSearchBots}
          onChange={(e) => setAllowSearchBots(e.target.checked)}
          className="rounded border-green-300 dark:border-green-700 text-green-600 focus:ring-green-500 bg-white dark:bg-slate-700 focus:ring-offset-0 dark:focus:ring-offset-slate-800"
        />
        <div>
          <span className="text-sm font-medium text-green-800 dark:text-green-300 flex items-center gap-2">
            {t('form.security.cloudProvider.allowSearchBots', 'Allow Search Bots')}
            <HelpTip contentKey="help.security.cloudProviderAllowSearchBots" />
          </span>
          <p className="text-xs text-green-600 dark:text-green-400">
            {t('form.security.cloudProvider.allowSearchBotsDescription', 'Allow search engine bots (Google, Bing, etc.) to bypass cloud blocking')}
          </p>
        </div>
      </label>

      {/* Quick Actions */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
            {t('form.security.cloudProvider.selectProviders', 'Select Providers')}
          </label>
          <div className="flex gap-1">
            <button
              type="button"
              onClick={selectAll}
              className="px-2 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300 bg-emerald-100 dark:bg-emerald-900/30 hover:bg-emerald-200 dark:hover:bg-emerald-900/50 rounded transition-colors"
            >
              {t('common:buttons.selectAll', 'Select All')}
            </button>
            <button
              type="button"
              onClick={clearAll}
              className="px-2 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded transition-colors"
            >
              {t('common:buttons.clearAll', 'Clear All')}
            </button>
          </div>
        </div>

        {/* Quick Add Presets */}
        <div className="flex flex-wrap gap-1 pt-1">
          <span className="text-xs text-slate-500 dark:text-slate-400 mr-1">{t('form.security.cloudProvider.quickAdd', 'Quick Add')}:</span>
          <button type="button" onClick={() => applyPreset(QUICK_PRESETS.majorClouds)} className="px-2 py-0.5 text-xs font-medium text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 rounded transition-colors">
            + {t('form.security.cloudProvider.majorClouds', 'Major Clouds')}
          </button>
          <button type="button" onClick={() => applyPreset(QUICK_PRESETS.budgetVps)} className="px-2 py-0.5 text-xs font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 hover:bg-amber-100 dark:hover:bg-amber-900/40 rounded transition-colors">
            + {t('form.security.cloudProvider.budgetVps', 'Budget VPS')}
          </button>
          <button type="button" onClick={() => applyPreset(QUICK_PRESETS.asiaProviders)} className="px-2 py-0.5 text-xs font-medium text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-900/20 hover:bg-purple-100 dark:hover:bg-purple-900/40 rounded transition-colors">
            + {t('form.security.cloudProvider.asiaProviders', 'Asian Clouds')}
          </button>
        </div>
      </div>

      {/* Provider List */}
      <div className="max-h-64 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg p-2 bg-white dark:bg-slate-800/50">
        {(['us', 'eu', 'cn', 'kr'] as const).map((region) => {
          const regionProviders = providers[region]
          if (regionProviders.length === 0) return null
          const regionSlugs = regionProviders.map((p) => p.slug)
          const allSelected = regionSlugs.every((slug) => blockedProviders.includes(slug)) && regionSlugs.length > 0
          return (
            <div key={region} className="mb-2 last:mb-0">
              <div className="flex items-center justify-between px-2 py-1 bg-slate-50 dark:bg-slate-700/50 rounded mb-1">
                <div className="flex items-center gap-2">
                  <span>{REGION_FLAGS[region]}</span>
                  <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">{t(`form.security.cloudProvider.regions.${region}`)}</span>
                </div>
                <button type="button" onClick={() => toggleAllInRegion(region)} className="text-[10px] text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium">
                  {allSelected ? t('common:buttons.deselectAll') : t('common:buttons.selectAll')}
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1">
                {regionProviders.map((provider) => {
                  const isSelected = blockedProviders.includes(provider.slug)
                  return (
                    <label key={provider.slug} className={`flex items-start gap-2 p-1.5 rounded cursor-pointer text-sm ${isSelected ? 'bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-slate-50 dark:hover:bg-slate-700/50'}`}>
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleProvider(provider.slug)}
                        className="mt-0.5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700 focus:ring-offset-0 dark:focus:ring-offset-slate-800"
                      />
                      <div className="min-w-0 flex-1">
                        <span className={`block text-xs ${isSelected ? 'font-medium text-blue-900 dark:text-blue-300' : 'text-slate-700 dark:text-slate-300'}`}>
                          {provider.name}
                        </span>
                        <span className="block text-[10px] text-slate-400 dark:text-slate-500">
                          {provider.ip_count.toLocaleString()} IPs
                        </span>
                      </div>
                    </label>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

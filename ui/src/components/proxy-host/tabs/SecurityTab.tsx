import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { CreateProxyHostRequest } from '../../../types/proxy-host'
import type { BotFilterState, GeoDataState } from '../types'
import type { CreateFail2banRequest } from '../../../types/security'
import { WAFSettings } from './security/WAFSettings'
import { BotFilterSettings } from './security/BotFilterSettings'
import { GeoIPSettings } from './security/GeoIPSettings'
import { PriorityAllowIPs } from './security/PriorityAllowIPs'
import { CloudProviderBlocking } from './security/CloudProviderBlocking'
import { AuthProviderSettings } from './security/AuthProviderSettings'
import { CollapsibleSection } from './security/CollapsibleSection'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../common/HelpTip'
import { Link } from 'react-router-dom'
import { getFail2ban, updateFail2ban } from '../../../api/security'

interface SecurityTabProps {
  hostId?: string
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  botFilterData: BotFilterState
  setBotFilterData: React.Dispatch<React.SetStateAction<BotFilterState>>
  geoData: GeoDataState
  setGeoData: React.Dispatch<React.SetStateAction<GeoDataState>>
  geoSearchTerm: string
  setGeoSearchTerm: (value: string) => void
  allowedIPsInput: string
  setAllowedIPsInput: (value: string) => void
  blockedCloudProviders: string[]
  setBlockedCloudProviders: (providers: string[]) => void
  cloudProviderChallengeMode: boolean
  setCloudProviderChallengeMode: (enabled: boolean) => void
  cloudProviderAllowSearchBots: boolean
  setCloudProviderAllowSearchBots: (enabled: boolean) => void
  availableAccessLists: Array<{
    id: string
    name: string
    satisfy_any: boolean
  }>
  availableAuthProviders: Array<{
    id: string
    name: string
    type: string
  }>
  geoipStatus: { status: string } | undefined
  countryCodes: Record<string, string> | undefined
}

export function SecurityTabContent({
  hostId,
  formData,
  setFormData,
  botFilterData,
  setBotFilterData,
  geoData,
  setGeoData,
  geoSearchTerm,
  setGeoSearchTerm,
  allowedIPsInput,
  setAllowedIPsInput,
  blockedCloudProviders,
  setBlockedCloudProviders,
  cloudProviderChallengeMode,
  setCloudProviderChallengeMode,
  cloudProviderAllowSearchBots,
  setCloudProviderAllowSearchBots,
  availableAccessLists,
  availableAuthProviders,
  geoipStatus,
  countryCodes,
}: SecurityTabProps) {
  const { t } = useTranslation('proxyHost')
  const queryClient = useQueryClient()

  // ForwardAuth and managed challenges (geo/cloud CAPTCHA) both emit an
  // auth_request in `location /`; nginx allows only one. Enforce mutual
  // exclusion: when a provider is selected the challenge toggles are
  // disabled; when a challenge is enabled the provider is cleared.
  const challengeActive = geoData.challenge_mode || cloudProviderChallengeMode

  const clearAuthProvider = () =>
    setFormData((prev) => ({ ...prev, auth_provider_id: undefined, auth_bypass_paths: [] }))

  const setGeoDataWithLock: React.Dispatch<React.SetStateAction<GeoDataState>> = (value) => {
    setGeoData((prev) => {
      const next = typeof value === 'function' ? (value as (p: GeoDataState) => GeoDataState)(prev) : value
      if (next.challenge_mode && !prev.challenge_mode) clearAuthProvider()
      return next
    })
  }

  const setCloudChallengeWithLock = (enabled: boolean) => {
    if (enabled) clearAuthProvider()
    setCloudProviderChallengeMode(enabled)
  }

  // Fail2ban state management
  const [fail2banEnabled, setFail2banEnabled] = useState(false)
  const [fail2banInitialized, setFail2banInitialized] = useState(false)

  const fail2banQuery = useQuery({
    queryKey: ['fail2ban', hostId],
    queryFn: () => getFail2ban(hostId!),
    enabled: !!hostId,
    retry: false,
  })

  useEffect(() => {
    if (fail2banQuery.data && !fail2banInitialized) {
      setFail2banEnabled(fail2banQuery.data.enabled)
      setFail2banInitialized(true)
    } else if (fail2banQuery.error && !fail2banInitialized) {
      setFail2banInitialized(true)
    }
  }, [fail2banQuery.data, fail2banQuery.error, fail2banInitialized])

  const fail2banMutation = useMutation({
    mutationFn: (data: CreateFail2banRequest) => updateFail2ban(hostId!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fail2ban', hostId] })
    },
  })

  const handleFail2banToggle = useCallback((enabled: boolean) => {
    setFail2banEnabled(enabled)
    if (hostId) {
      // Get current settings or use defaults
      const currentData = fail2banQuery.data || {
        max_retries: 5,
        find_time: 600,
        ban_time: 3600,
        fail_codes: '401,403',
        action: 'block',
      }
      fail2banMutation.mutate({
        enabled,
        max_retries: currentData.max_retries,
        find_time: currentData.find_time,
        ban_time: currentData.ban_time,
        fail_codes: currentData.fail_codes,
        action: currentData.action,
      })
    }
  }, [hostId, fail2banQuery.data, fail2banMutation])

  return (
    <div className="space-y-6">
      {/* Priority Allow IPs - Always visible at the top */}
      <CollapsibleSection title={t('form.security.priorityAllowIPs.title')}>
        <PriorityAllowIPs
          allowedIPsInput={allowedIPsInput}
          setAllowedIPsInput={setAllowedIPsInput}
          geoData={geoData}
          setGeoData={setGeoData}
        />
      </CollapsibleSection>

      {/* Block Exploits */}
      <CollapsibleSection title={t('form.security.blockExploits')}>
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 space-y-4">
        <div className="flex items-start gap-3">
          <div className="flex items-center h-5 mt-1">
            <input
              type="checkbox"
              checked={formData.block_exploits}
              onChange={(e) =>
                setFormData((prev) => ({ ...prev, block_exploits: e.target.checked }))
              }
              className="w-4 h-4 text-primary-600 rounded border-slate-300 dark:border-slate-600 focus:ring-primary-500 dark:bg-slate-700"
            />
          </div>
          <div className="flex-1">
            <label className="text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
              {t('form.security.blockExploits')}
              <HelpTip contentKey="help.security.blockExploits" />
            </label>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('form.security.blockExploitsDescription')}
            </p>
          </div>
        </div>

        {/* Link to Exploit Rules Management - shown when block_exploits is enabled */}
        {formData.block_exploits && (
          <div className="ml-7 border-l-2 border-amber-300 dark:border-amber-600 pl-4">
            <div className="flex items-center justify-between bg-amber-50 dark:bg-amber-900/20 rounded-lg p-3">
              <div className="flex items-center gap-2">
                <svg className="w-5 h-5 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                    {t('form.security.exploitRulesManagement', 'Exploit Rules Management')}
                  </p>
                  <p className="text-xs text-amber-600 dark:text-amber-400">
                    {t('form.security.exploitRulesDescription', 'Manage exploit blocking rules and exceptions in the centralized WAF settings.')}
                  </p>
                </div>
              </div>
              <Link
                to="/waf/exploit-rules"
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-amber-600 hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-600 rounded-lg transition-colors"
              >
                {t('form.security.manageRules', 'Manage Rules')}
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </Link>
            </div>
          </div>
        )}
      </div>
      </CollapsibleSection>

      {/* Fail2ban - Auto IP Ban */}
      {hostId && (
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 space-y-4">
          <div className="flex items-start gap-3">
            <div className="flex items-center h-5 mt-1">
              <input
                type="checkbox"
                checked={fail2banEnabled}
                onChange={(e) => handleFail2banToggle(e.target.checked)}
                disabled={fail2banMutation.isPending}
                className="w-4 h-4 text-red-600 rounded border-slate-300 dark:border-slate-600 focus:ring-red-500 dark:bg-slate-700"
              />
            </div>
            <div className="flex-1">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
                {t('form.security.fail2ban', 'Fail2ban (Auto IP Ban)')}
                <HelpTip contentKey="help.security.fail2ban" />
                {fail2banMutation.isPending && (
                  <svg className="w-3 h-3 animate-spin text-slate-400" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                )}
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {t('form.security.fail2banDescription', 'Automatically ban IPs after repeated failed attempts (401/403 errors).')}
              </p>
            </div>
          </div>

          {/* Link to Fail2ban Settings - shown when fail2ban is enabled */}
          {fail2banEnabled && (
            <div className="ml-7 border-l-2 border-red-300 dark:border-red-600 pl-4">
              <div className="flex items-center justify-between bg-red-50 dark:bg-red-900/20 rounded-lg p-3">
                <div className="flex items-center gap-2">
                  <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                  </svg>
                  <div>
                    <p className="text-sm font-medium text-red-800 dark:text-red-300">
                      {t('form.security.fail2banSettings', 'Fail2ban Settings')}
                    </p>
                    <p className="text-xs text-red-600 dark:text-red-400">
                      {t('form.security.fail2banSettingsDescription', 'Configure ban time, max retries, and other settings.')}
                    </p>
                  </div>
                </div>
                <Link
                  to="/waf/fail2ban"
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-white bg-red-600 hover:bg-red-700 dark:bg-red-500 dark:hover:bg-red-600 rounded-lg transition-colors"
                >
                  {t('form.security.configureSettings', 'Configure')}
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </Link>
              </div>
            </div>
          )}
        </div>
      )}

      {/* WAF Settings */}
      <CollapsibleSection title={t('form.waf.title')}>
        <WAFSettings formData={formData} setFormData={setFormData} />
      </CollapsibleSection>

      {/* Access Control */}
      <CollapsibleSection title={t('form.security.accessList')}>
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          {t('form.security.accessList')}
          <HelpTip contentKey="help.security.accessList" />
        </label>
        <select
          value={formData.access_list_id || ''}
          onChange={(e) =>
            setFormData((prev) => ({
              ...prev,
              access_list_id: e.target.value || '',
            }))
          }
          className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
        >
          <option value="">{t('form.security.noAccessList')}</option>
          {availableAccessLists.map((list) => (
            <option key={list.id} value={list.id}>
              {list.name} ({list.satisfy_any ? 'Any condition' : 'All conditions'})
            </option>
          ))}
        </select>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          {t('form.security.selectAccessList')}
        </p>
      </div>
      </CollapsibleSection>

      {/* Auth Provider (ForwardAuth / SSO) */}
      <CollapsibleSection title={t('form.security.authProvider', 'Auth Provider (SSO)')}>
        <AuthProviderSettings
          availableAuthProviders={availableAuthProviders}
          selectedProviderId={formData.auth_provider_id || ''}
          bypassPaths={formData.auth_bypass_paths || []}
          challengeActive={challengeActive}
          onSelect={(id) =>
            setFormData((prev) => ({ ...prev, auth_provider_id: id || undefined }))
          }
          onBypassChange={(paths) =>
            setFormData((prev) => ({ ...prev, auth_bypass_paths: paths }))
          }
        />
      </CollapsibleSection>

      {/* Bot Filter Settings */}
      <CollapsibleSection title={t('form.security.botFilter.title')}>
        <BotFilterSettings botFilterData={botFilterData} setBotFilterData={setBotFilterData} />
      </CollapsibleSection>

      {/* GeoIP Settings */}
      <CollapsibleSection title={t('form.security.geoip.title')}>
        <GeoIPSettings
          geoData={geoData}
          setGeoData={setGeoDataWithLock}
          geoSearchTerm={geoSearchTerm}
          setGeoSearchTerm={setGeoSearchTerm}
          geoipStatus={geoipStatus}
          countryCodes={countryCodes}
        />
      </CollapsibleSection>

      {/* Cloud Provider Blocking */}
      <CollapsibleSection title={t('form.security.cloudProvider.title')}>
        <CloudProviderBlocking
          blockedProviders={blockedCloudProviders}
          setBlockedProviders={setBlockedCloudProviders}
          challengeMode={cloudProviderChallengeMode}
          setChallengeMode={setCloudChallengeWithLock}
          allowSearchBots={cloudProviderAllowSearchBots}
          setAllowSearchBots={setCloudProviderAllowSearchBots}
        />
      </CollapsibleSection>
    </div>
  )
}

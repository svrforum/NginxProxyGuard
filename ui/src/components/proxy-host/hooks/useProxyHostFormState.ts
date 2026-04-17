import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listCertificates } from '../../../api/certificates'
import { listDNSProviders } from '../../../api/dns-providers'
import { getAccessLists, getCountryCodes, getGeoRestriction } from '../../../api/access'
import { getBotFilter } from '../../../api/security'
import { getGeoIPStatus } from '../../../api/settings'
import { api } from '../../../api/client'
import type { ProxyHost, CreateProxyHostRequest } from '../../../types/proxy-host'
import type { CreateCertificateRequest } from '../../../types/certificate'
import type { BotFilterState, FormErrors, GeoDataState } from '../types'

/** Public return type is inferred from {@link useProxyHostFormState}. */
export type ProxyHostFormStateResult = ReturnType<typeof useProxyHostFormState>

/**
 * Owns all form-field state and the external data the form reads from the
 * API. Split out from useProxyHostForm so the composition hook stays thin.
 *
 * NOTE: The submit orchestrator lives in a separate hook and receives this
 * whole object so it can call the same setters.
 */
export function useProxyHostFormState(host: ProxyHost | null | undefined) {
  const isEditing = !!host

  // Form data state
  const [formData, setFormData] = useState<CreateProxyHostRequest>({
    domain_names: [''],
    forward_scheme: 'http',
    forward_host: '',
    forward_port: 80,
    ssl_enabled: false,
    ssl_force_https: false,
    ssl_http2: true,
    ssl_http3: false,
    certificate_id: undefined,
    access_list_id: undefined,
    allow_websocket_upgrade: true,
    cache_enabled: false,
    cache_static_only: true,
    cache_ttl: '7d',
    block_exploits: true,
    // Host-level proxy settings (empty = use global)
    client_max_body_size: '',
    proxy_max_temp_file_size: '',
    proxy_buffering: '',
    proxy_request_buffering: '',
    waf_enabled: false,
    waf_mode: 'blocking',
    waf_paranoia_level: 1,
    waf_anomaly_threshold: 5,
    advanced_config: '',
    enabled: true,
  })

  // Port input state - initialize from host if editing
  const [portInput, setPortInput] = useState(() =>
    host?.forward_port?.toString() || '80',
  )

  // Errors state
  const [errors, setErrors] = useState<FormErrors>({})

  // Certificate state
  const [certMode, setCertMode] = useState<'select' | 'create'>('select')
  const [newCertData, setNewCertData] = useState<CreateCertificateRequest>({
    domain_names: [],
    provider: 'letsencrypt',
    auto_renew: true,
  })

  // Bot filter state
  const [botFilterData, setBotFilterData] = useState<BotFilterState>({
    enabled: false,
    block_bad_bots: true,
    block_ai_bots: false,
    allow_search_engines: true,
    block_suspicious_clients: false,
    custom_blocked_agents: '',
    custom_allowed_agents: '',
    challenge_suspicious: false,
  })

  // GeoIP state
  const [geoData, setGeoData] = useState<GeoDataState>({
    enabled: false,
    mode: 'blacklist',
    countries: [],
    allowed_ips: [],
    allow_private_ips: true,
    allow_search_bots: false,
    challenge_mode: false,
  })
  const [geoSearchTerm, setGeoSearchTerm] = useState('')
  const [allowedIPsInput, setAllowedIPsInput] = useState('')

  // Cloud provider blocking state
  const [blockedCloudProviders, setBlockedCloudProviders] = useState<string[]>([])
  const [cloudProviderChallengeMode, setCloudProviderChallengeMode] = useState(false)
  const [cloudProviderAllowSearchBots, setCloudProviderAllowSearchBots] = useState(false)

  // ───── Queries ────────────────────────────────────────────────────────
  const { data: certificatesData } = useQuery({
    queryKey: ['certificates'],
    queryFn: () => listCertificates(),
  })

  const { data: accessListsData } = useQuery({
    queryKey: ['accessLists'],
    queryFn: () => getAccessLists(1, 100),
  })

  const { data: dnsProvidersData } = useQuery({
    queryKey: ['dnsProviders'],
    queryFn: () => listDNSProviders(1, 100),
  })

  const { data: existingBotFilter } = useQuery({
    queryKey: ['botFilter', host?.id],
    queryFn: () => getBotFilter(host!.id),
    enabled: !!host?.id,
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

  const { data: existingGeoRestriction } = useQuery({
    queryKey: ['geoRestriction', host?.id],
    queryFn: () => getGeoRestriction(host!.id).catch(() => null),
    enabled: !!host?.id && !!isGeoIPAvailable,
  })

  const { data: existingCloudProviderSettings } = useQuery({
    queryKey: ['blockedCloudProviders', host?.id],
    queryFn: async () => {
      const response = await api.get<{
        blocked_providers: string[]
        challenge_mode: boolean
        allow_search_bots: boolean
      }>(`/api/v1/proxy-hosts/${host!.id}/blocked-cloud-providers`)
      return {
        blocked_providers: response.blocked_providers || [],
        challenge_mode: response.challenge_mode || false,
        allow_search_bots: response.allow_search_bots || false,
      }
    },
    enabled: !!host?.id,
  })

  // ───── Derived data ──────────────────────────────────────────────────
  const availableCerts = certificatesData?.data?.filter((c) => c.status === 'issued') || []
  const pendingCerts = certificatesData?.data?.filter((c) => c.status === 'pending') || []
  const availableAccessLists = accessListsData?.data || []
  const dnsProviders = dnsProvidersData?.data || []

  // ───── Effects: hydrate form state from server data ──────────────────
  useEffect(() => {
    if (existingBotFilter) {
      setBotFilterData({
        enabled: existingBotFilter.enabled,
        block_bad_bots: existingBotFilter.block_bad_bots,
        block_ai_bots: existingBotFilter.block_ai_bots,
        allow_search_engines: existingBotFilter.allow_search_engines,
        block_suspicious_clients: existingBotFilter.block_suspicious_clients,
        custom_blocked_agents: existingBotFilter.custom_blocked_agents || '',
        custom_allowed_agents: existingBotFilter.custom_allowed_agents || '',
        challenge_suspicious: existingBotFilter.challenge_suspicious,
      })
    }
  }, [existingBotFilter])

  useEffect(() => {
    if (existingGeoRestriction) {
      setGeoData({
        enabled: existingGeoRestriction.enabled && existingGeoRestriction.countries?.length > 0,
        mode: existingGeoRestriction.mode,
        countries: existingGeoRestriction.countries || [],
        allowed_ips: existingGeoRestriction.allowed_ips || [],
        allow_private_ips: existingGeoRestriction.allow_private_ips ?? true,
        allow_search_bots: existingGeoRestriction.allow_search_bots ?? false,
        challenge_mode: existingGeoRestriction.challenge_mode || false,
      })
      setAllowedIPsInput((existingGeoRestriction.allowed_ips || []).join('\n'))
    }
  }, [existingGeoRestriction])

  useEffect(() => {
    if (existingCloudProviderSettings) {
      setBlockedCloudProviders(existingCloudProviderSettings.blocked_providers)
      setCloudProviderChallengeMode(existingCloudProviderSettings.challenge_mode)
      setCloudProviderAllowSearchBots(existingCloudProviderSettings.allow_search_bots || false)
    }
  }, [existingCloudProviderSettings])

  useEffect(() => {
    const domains = formData.domain_names.filter((d) => d.trim())
    if (domains.length > 0 && certMode === 'create') {
      setNewCertData((prev) => ({ ...prev, domain_names: domains }))
    }
  }, [formData.domain_names, certMode])

  useEffect(() => {
    if (host) {
      setFormData({
        domain_names: host.domain_names,
        forward_scheme: host.forward_scheme,
        forward_host: host.forward_host,
        forward_port: host.forward_port,
        ssl_enabled: host.ssl_enabled,
        ssl_force_https: host.ssl_force_https,
        ssl_http2: host.ssl_http2,
        ssl_http3: host.ssl_http3,
        certificate_id: host.certificate_id,
        access_list_id: host.access_list_id,
        allow_websocket_upgrade: host.allow_websocket_upgrade,
        cache_enabled: host.cache_enabled,
        cache_static_only: host.cache_static_only ?? true,
        cache_ttl: host.cache_ttl || '7d',
        block_exploits: host.block_exploits,
        // Host-level proxy settings
        client_max_body_size: host.client_max_body_size || '',
        proxy_max_temp_file_size: host.proxy_max_temp_file_size || '',
        proxy_buffering: host.proxy_buffering || '',
        proxy_request_buffering: host.proxy_request_buffering || '',
        waf_enabled: host.waf_enabled,
        waf_mode: (host.waf_mode as 'blocking' | 'detection') || 'blocking',
        waf_paranoia_level: host.waf_paranoia_level || 1,
        waf_anomaly_threshold: host.waf_anomaly_threshold || 5,
        advanced_config: host.advanced_config || '',
        enabled: host.enabled,
      })
      setPortInput(host.forward_port.toString())
    }
  }, [host])

  return {
    // Form data
    formData,
    setFormData,
    portInput,
    setPortInput,
    errors,
    setErrors,

    // Certificate form
    certMode,
    setCertMode,
    newCertData,
    setNewCertData,

    // Bot filter
    botFilterData,
    setBotFilterData,

    // GeoIP
    geoData,
    setGeoData,
    geoSearchTerm,
    setGeoSearchTerm,
    allowedIPsInput,
    setAllowedIPsInput,

    // Cloud provider blocking
    blockedCloudProviders,
    setBlockedCloudProviders,
    cloudProviderChallengeMode,
    setCloudProviderChallengeMode,
    cloudProviderAllowSearchBots,
    setCloudProviderAllowSearchBots,

    // External data
    availableCerts,
    pendingCerts,
    availableAccessLists,
    dnsProviders,
    geoipStatus,
    countryCodes,
    existingGeoRestriction,

    // Flags
    isEditing,
  }
}

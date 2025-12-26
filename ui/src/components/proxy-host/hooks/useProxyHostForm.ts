import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createProxyHost, updateProxyHost, syncAllConfigs } from '../../../api/proxy-hosts'
import { listCertificates, createCertificate, getCertificate } from '../../../api/certificates'
import { listDNSProviders } from '../../../api/dns-providers'
import { getAccessLists, getGeoRestriction, setGeoRestriction, deleteGeoRestriction, getCountryCodes } from '../../../api/access'
import { getBotFilter, updateBotFilter } from '../../../api/security'
import { getGeoIPStatus } from '../../../api/settings'
import { api, ApiError } from '../../../api/client'
import type { ProxyHost, CreateProxyHostRequest } from '../../../types/proxy-host'
import type { CreateCertificateRequest } from '../../../types/certificate'
import type { BotFilterState, GeoDataState, FormErrors, CertificateState } from '../types'

export function useProxyHostForm(host: ProxyHost | null | undefined, onClose: () => void) {
  const queryClient = useQueryClient()
  const { t } = useTranslation('proxyHost')
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
    waf_enabled: false,
    waf_mode: 'blocking',
    waf_paranoia_level: 1,
    waf_anomaly_threshold: 5,
    advanced_config: '',
    enabled: true,
  })

  // Port input state - initialize from host if editing
  const [portInput, setPortInput] = useState(() =>
    host?.forward_port?.toString() || '80'
  )

  // Errors state
  const [errors, setErrors] = useState<FormErrors>({})

  // Save progress state
  const [saveProgress, setSaveProgress] = useState({
    isOpen: false,
    currentStep: 0,
    error: null as string | null,
    errorDetails: null as string | null,
  })

  // Certificate state
  const [certMode, setCertMode] = useState<'select' | 'create'>('select')
  const [newCertData, setNewCertData] = useState<CreateCertificateRequest>({
    domain_names: [],
    provider: 'letsencrypt',
    auto_renew: true,
  })
  const [certCreating, setCertCreating] = useState(false)
  const [certError, setCertError] = useState<string | null>(null)
  const [certSuccess, setCertSuccess] = useState<string | null>(null)
  const [certProgress, setCertProgress] = useState<string | null>(null)
  const [certElapsedTime, setCertElapsedTime] = useState(0)
  const [pendingCertId, setPendingCertId] = useState<string | null>(null) // For log modal

  // Bot filter state
  const [botFilterData, setBotFilterData] = useState<BotFilterState>({
    enabled: false,
    block_bad_bots: true,
    block_ai_bots: false,
    allow_search_engines: true,
    block_suspicious_clients: false,
    custom_blocked_agents: '',
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

  // Queries
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

  const isGeoIPAvailable = geoipStatus?.status === 'active' || (geoipStatus?.enabled && geoipStatus?.country_db)

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
      const response = await api.get<{ blocked_providers: string[]; challenge_mode: boolean; allow_search_bots: boolean }>(`/api/v1/proxy-hosts/${host!.id}/blocked-cloud-providers`)
      return {
        blocked_providers: response.blocked_providers || [],
        challenge_mode: response.challenge_mode || false,
        allow_search_bots: response.allow_search_bots || false,
      }
    },
    enabled: !!host?.id,
  })

  // Derived data
  const availableCerts = certificatesData?.data?.filter((c) => c.status === 'issued') || []
  const pendingCerts = certificatesData?.data?.filter((c) => c.status === 'pending') || []
  const availableAccessLists = accessListsData?.data || []
  const dnsProviders = dnsProvidersData?.data || []

  // Effects
  useEffect(() => {
    if (existingBotFilter) {
      setBotFilterData({
        enabled: existingBotFilter.enabled,
        block_bad_bots: existingBotFilter.block_bad_bots,
        block_ai_bots: existingBotFilter.block_ai_bots,
        allow_search_engines: existingBotFilter.allow_search_engines,
        block_suspicious_clients: existingBotFilter.block_suspicious_clients,
        custom_blocked_agents: existingBotFilter.custom_blocked_agents || '',
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
    const domains = formData.domain_names.filter(d => d.trim())
    if (domains.length > 0 && certMode === 'create') {
      setNewCertData(prev => ({ ...prev, domain_names: domains }))
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

  // Helper to close progress modal after delay
  const closeProgressWithDelay = (delay = 800) => {
    setTimeout(() => {
      setSaveProgress({ isOpen: false, currentStep: 0, error: null, errorDetails: null })
      onClose()
    }, delay)
  }

  // Mutations
  const createMutation = useMutation({
    mutationFn: createProxyHost,
    onMutate: () => {
      // Step 0: Server processing (DB + config + test + reload)
      setSaveProgress(prev => ({ ...prev, currentStep: 0 }))
    },
    onSuccess: async (newHost) => {
      // Step 1: Additional settings
      setSaveProgress(prev => ({ ...prev, currentStep: 1 }))

      // Save additional settings in PARALLEL for speed (skip nginx reload since main API already did it)
      const additionalSettingsPromises: Promise<unknown>[] = []

      if (botFilterData.enabled || botFilterData.custom_blocked_agents) {
        additionalSettingsPromises.push(
          updateBotFilter(newHost.id, botFilterData, true)
            .catch(err => console.error('Failed to save bot filter:', err))
        )
      }

      // Save geo restriction if geo blocking enabled OR if priority allow IPs exist
      if ((geoData.enabled && geoData.countries.length > 0) || (geoData.allowed_ips?.length ?? 0) > 0) {
        additionalSettingsPromises.push(
          setGeoRestriction(newHost.id, {
            mode: geoData.mode,
            countries: geoData.countries,
            allowed_ips: geoData.allowed_ips,
            allow_private_ips: geoData.allow_private_ips,
            allow_search_bots: geoData.allow_search_bots,
            enabled: geoData.enabled && geoData.countries.length > 0,
            challenge_mode: geoData.challenge_mode,
          }, true).catch(err => console.error('Failed to save geo restriction:', err))
        )
      }

      if (blockedCloudProviders.length > 0 || cloudProviderChallengeMode || cloudProviderAllowSearchBots) {
        additionalSettingsPromises.push(
          api.put(`/api/v1/proxy-hosts/${newHost.id}/blocked-cloud-providers?skip_reload=true`, {
            blocked_providers: blockedCloudProviders,
            challenge_mode: cloudProviderChallengeMode,
            allow_search_bots: cloudProviderAllowSearchBots,
          }).catch(err => console.error('Failed to save blocked cloud providers:', err))
        )
      }

      if (additionalSettingsPromises.length > 0) {
        await Promise.all(additionalSettingsPromises)
        // Final sync to regenerate config with all additional settings and reload nginx
        try {
          await syncAllConfigs()
        } catch (err) {
          console.error('Failed to sync configs after additional settings:', err)
        }
      }

      // Step 2: Complete
      setSaveProgress(prev => ({ ...prev, currentStep: 2 }))
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
      closeProgressWithDelay()
    },
    onError: (error) => {
      const isApiError = error instanceof ApiError
      setSaveProgress(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Failed to create proxy host',
        errorDetails: isApiError ? error.details || null : null,
      }))
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: CreateProxyHostRequest }) =>
      updateProxyHost(id, data),
    onMutate: () => {
      // Step 0: Server processing (DB + config + test + reload)
      setSaveProgress(prev => ({ ...prev, currentStep: 0 }))
    },
    onSuccess: async (_, variables) => {
      // Step 1: Additional settings
      setSaveProgress(prev => ({ ...prev, currentStep: 1 }))

      // Save additional settings in PARALLEL for speed (skip nginx reload since main API already did it)
      const additionalSettingsPromises = [
        // Bot filter (skip reload)
        updateBotFilter(variables.id, botFilterData, true)
          .then(() => queryClient.invalidateQueries({ queryKey: ['botFilter', variables.id] }))
          .catch(err => console.error('Failed to save bot filter:', err)),

        // Geo restriction (skip reload)
        // Save if geo blocking enabled OR if priority allow IPs exist
        (async () => {
          try {
            const hasGeoBlocking = geoData.enabled && geoData.countries.length > 0
            const hasPriorityAllowIPs = (geoData.allowed_ips?.length ?? 0) > 0

            if (hasGeoBlocking || hasPriorityAllowIPs) {
              await setGeoRestriction(variables.id, {
                mode: geoData.mode,
                countries: geoData.countries,
                allowed_ips: geoData.allowed_ips,
                allow_private_ips: geoData.allow_private_ips,
                allow_search_bots: geoData.allow_search_bots,
                enabled: hasGeoBlocking,
                challenge_mode: geoData.challenge_mode,
              }, true)
            } else if (existingGeoRestriction) {
              // Only delete if no geo blocking AND no priority allow IPs
              await deleteGeoRestriction(variables.id, true)
            }
            queryClient.invalidateQueries({ queryKey: ['geoRestriction', variables.id] })
          } catch (err) {
            console.error('Failed to save geo restriction:', err)
          }
        })(),

        // Blocked cloud providers (skip reload)
        api.put(`/api/v1/proxy-hosts/${variables.id}/blocked-cloud-providers?skip_reload=true`, {
          blocked_providers: blockedCloudProviders,
          challenge_mode: cloudProviderChallengeMode,
          allow_search_bots: cloudProviderAllowSearchBots,
        })
          .then(() => queryClient.invalidateQueries({ queryKey: ['blockedCloudProviders', variables.id] }))
          .catch(err => console.error('Failed to save blocked cloud providers:', err)),
      ]

      await Promise.all(additionalSettingsPromises)

      // Final sync to regenerate config with all additional settings and reload nginx
      try {
        await syncAllConfigs()
      } catch (err) {
        console.error('Failed to sync configs after additional settings:', err)
      }

      // Step 2: Complete
      setSaveProgress(prev => ({ ...prev, currentStep: 2 }))
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
      closeProgressWithDelay()
    },
    onError: (error) => {
      const isApiError = error instanceof ApiError
      setSaveProgress(prev => ({
        ...prev,
        error: error instanceof Error ? error.message : 'Failed to update proxy host',
        errorDetails: isApiError ? error.details || null : null,
      }))
    },
  })

  const mutation = isEditing ? updateMutation : createMutation

  // Validation
  const validate = (): boolean => {
    const newErrors: FormErrors = {}

    const domains = formData.domain_names.map((d) => d.trim()).filter((d) => d)
    if (domains.length === 0) {
      newErrors.domain_names = t('validation.domainAtLeastOne')
    }

    if (!formData.forward_host.trim()) {
      newErrors.forward_host = t('validation.hostRequired')
    }

    const port = parseInt(portInput)
    if (!portInput || isNaN(port) || port < 1 || port > 65535) {
      newErrors.forward_port = t('validation.portRange')
    }

    if (formData.ssl_enabled && certMode === 'select' && !formData.certificate_id) {
      newErrors.certificate_id = t('validation.certSelectionRequired')
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  // Certificate helper
  const waitForCertificate = async (certId: string, maxWaitTime = 120000): Promise<boolean> => {
    const startTime = Date.now()
    const pollInterval = 2000

    while (Date.now() - startTime < maxWaitTime) {
      const elapsed = Math.floor((Date.now() - startTime) / 1000)
      setCertElapsedTime(elapsed)

      try {
        const cert = await getCertificate(certId)

        // Null check for certificate response
        if (!cert) {
          console.error('Certificate not found:', certId)
          setCertProgress(`Issuing certificate... (${elapsed}s)`)
          await new Promise(resolve => setTimeout(resolve, pollInterval))
          continue
        }

        if (cert.status === 'issued') {
          setCertProgress('Certificate issued successfully!')
          return true
        } else if (cert.status === 'error') {
          setCertError(cert.error_message || 'Certificate issuance failed')
          return false
        } else {
          setCertProgress(`Issuing certificate... (${elapsed}s)`)
        }
      } catch (err) {
        console.error('Error polling certificate status:', err)
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval))
    }

    setCertError('Certificate issuance timed out. Please check the certificate status manually.')
    return false
  }

  // Submit handler
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // Step 0: Validation
    setSaveProgress({ isOpen: true, currentStep: 0, error: null, errorDetails: null })

    if (!validate()) {
      setSaveProgress({ isOpen: false, currentStep: 0, error: null, errorDetails: null })
      return
    }

    const domains = formData.domain_names.map((d) => d.trim()).filter((d) => d)
    let certificateId = formData.certificate_id

    if (formData.ssl_enabled && certMode === 'create') {
      if (domains.length === 0) {
        setErrors({ domain_names: t('validation.addDomainsBeforeCert') })
        setSaveProgress({ isOpen: false, currentStep: 0, error: null, errorDetails: null })
        return
      }

      setCertCreating(true)
      setCertError(null)
      setCertSuccess(null)
      setCertProgress('Creating certificate request...')
      setCertElapsedTime(0)
      // Close save progress modal while cert is being created
      setSaveProgress({ isOpen: false, currentStep: 0, error: null, errorDetails: null })

      try {
        const certData: CreateCertificateRequest = {
          ...newCertData,
          domain_names: domains,
        }
        const cert = await createCertificate(certData)
        setPendingCertId(cert.id) // Open log modal
        queryClient.invalidateQueries({ queryKey: ['certificates'] })

        if (cert.status === 'issued') {
          certificateId = cert.id
          setCertSuccess('Certificate created!')
          setPendingCertId(null) // Close log modal on success
        } else {
          setCertProgress('Waiting for certificate issuance...')
          const success = await waitForCertificate(cert.id)

          if (!success) {
            setCertCreating(false)
            // DON'T close the modal here - let user see the error
            // Modal will be closed when user clicks close button
            return
          }

          certificateId = cert.id
          setCertSuccess('Certificate issued successfully!')
          setPendingCertId(null) // Close log modal on success
        }
      } catch (err) {
        setCertError(err instanceof Error ? err.message : 'Failed to create certificate')
        setCertCreating(false)
        // DON'T close the modal here - let user see the error
        return
      }

      setCertProgress(null)
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      // Re-open save progress modal after cert is created
      setSaveProgress({ isOpen: true, currentStep: 0, error: null, errorDetails: null })
    }

    const data = {
      ...formData,
      domain_names: domains,
      forward_port: parseInt(portInput) || 80,
      certificate_id: certificateId,
    }

    if (isEditing && host) {
      updateMutation.mutate({ id: host.id, data })
    } else {
      createMutation.mutate(data)
    }

    setCertCreating(false)
  }

  // Close progress modal on error
  const closeSaveProgress = () => {
    setSaveProgress({ isOpen: false, currentStep: 0, error: null, errorDetails: null })
  }

  // Close certificate log modal
  const closeCertLogModal = () => {
    setPendingCertId(null)
  }

  // Domain helpers
  const addDomain = () => {
    setFormData((prev) => ({
      ...prev,
      domain_names: [...prev.domain_names, ''],
    }))
  }

  const removeDomain = (index: number) => {
    setFormData((prev) => ({
      ...prev,
      domain_names: prev.domain_names.filter((_, i) => i !== index),
    }))
  }

  const updateDomain = (index: number, value: string) => {
    setFormData((prev) => ({
      ...prev,
      domain_names: prev.domain_names.map((d, i) => (i === index ? value : d)),
    }))
  }

  // Certificate state object
  const certState: CertificateState = {
    mode: certMode,
    data: newCertData,
    creating: certCreating,
    error: certError,
    success: certSuccess,
    progress: certProgress,
    elapsedTime: certElapsedTime,
  }

  return {
    // State
    formData,
    setFormData,
    portInput,
    setPortInput,
    errors,
    setErrors,
    isEditing,

    // Certificate
    certState,
    setCertMode,
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

    // Data from queries
    availableCerts,
    pendingCerts,
    availableAccessLists,
    dnsProviders,
    geoipStatus,
    countryCodes,

    // Mutations
    mutation,
    certCreating,

    // Save progress
    saveProgress,
    closeSaveProgress,

    // Certificate log modal
    pendingCertId,
    closeCertLogModal,

    // Handlers
    handleSubmit,
    addDomain,
    removeDomain,
    updateDomain,
  }
}

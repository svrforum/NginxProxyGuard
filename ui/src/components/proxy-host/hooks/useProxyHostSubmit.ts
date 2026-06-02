import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  createProxyHost,
  regenerateHostConfig,
  updateProxyHost,
} from '../../../api/proxy-hosts'
import { ApiError } from '../../../api/client'
import type { CreateProxyHostRequest, ProxyHost } from '../../../types/proxy-host'
import { isFormValid, normalizeDomains, validateProxyHostForm } from './proxyHostValidation'
import type { ProxyHostCertificate } from './useProxyHostCertificate'
import type { ProxyHostExtras } from './useProxyHostExtras'
import type { ProxyHostFormStateResult } from './useProxyHostFormState'

/** Save progress modal state. */
export interface SaveProgressState {
  isOpen: boolean
  currentStep: number
  error: string | null
  errorDetails: string | null
}

interface UseProxyHostSubmitArgs {
  host: ProxyHost | null | undefined
  state: ProxyHostFormStateResult
  cert: ProxyHostCertificate
  extras: ProxyHostExtras
  onClose: () => void
}

/** Fresh save-progress state — closed modal, no error. */
const INITIAL_PROGRESS: SaveProgressState = {
  isOpen: false,
  currentStep: 0,
  error: null,
  errorDetails: null,
}

/**
 * Orchestrates the submit flow for the proxy host form. Responsible
 * for the multi-step pipeline:
 *
 *  1. Validation (fail → early return)
 *  2. Cert create + poll (when SSL on and certMode === 'create')
 *  3. POST / PUT the proxy host itself
 *  4. Fan-out additional settings saves (bot/geo/cloud w/ skip_reload=true)
 *  5. Single nginx config regenerate
 *  6. Close modal + invalidate queries
 */
export function useProxyHostSubmit({
  host,
  state,
  cert,
  extras,
  onClose,
}: UseProxyHostSubmitArgs) {
  const queryClient = useQueryClient()
  const { t } = useTranslation('proxyHost')
  const isEditing = !!host
  const isStreamMode = state.formData.proxy_type === 'stream'

  const [saveProgress, setSaveProgress] = useState<SaveProgressState>(INITIAL_PROGRESS)

  /** Helper to close the progress modal after a short delay. */
  function closeProgressWithDelay(delay = 800) {
    setTimeout(() => {
      setSaveProgress(INITIAL_PROGRESS)
      onClose()
    }, delay)
  }

  /**
   * Translate a thrown error into the `error` + `errorDetails` shape
   * used by the SaveProgressModal.
   */
  function errorToProgress(err: unknown, fallback: string) {
    const isApiError = err instanceof ApiError
    return {
      error: err instanceof Error ? err.message : fallback,
      errorDetails: isApiError ? err.details || null : null,
    }
  }

  // ───── Create mutation ──────────────────────────────────────────────
  const createMutation = useMutation({
    mutationFn: createProxyHost,
    onMutate: () => {
      // Step 0: Server processing (DB + config + test + reload)
      setSaveProgress((prev) => ({ ...prev, currentStep: 0 }))
    },
    onSuccess: async (newHost) => {
      // Step 1: Additional settings
      setSaveProgress((prev) => ({ ...prev, currentStep: 1 }))

      const savedAny = newHost.proxy_type === 'stream'
        ? false
        : await extras.saveExtrasForCreate({
          hostId: newHost.id,
          botFilterData: state.botFilterData,
          geoData: state.geoData,
          blockedCloudProviders: state.blockedCloudProviders,
          cloudProviderChallengeMode: state.cloudProviderChallengeMode,
          cloudProviderAllowSearchBots: state.cloudProviderAllowSearchBots,
        })

      if (savedAny) {
        // Regenerate config for this specific host to apply additional settings
        try {
          await regenerateHostConfig(newHost.id)
        } catch (err) {
          setSaveProgress((prev) => ({
            ...prev,
            ...errorToProgress(err, 'Failed to apply nginx config'),
          }))
          return
        }
      }

      // Step 2: Complete
      setSaveProgress((prev) => ({ ...prev, currentStep: 2 }))
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
      closeProgressWithDelay()
    },
    onError: (error) => {
      setSaveProgress((prev) => ({
        ...prev,
        ...errorToProgress(error, 'Failed to create proxy host'),
      }))
    },
  })

  // ───── Update mutation ──────────────────────────────────────────────
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: CreateProxyHostRequest }) =>
      updateProxyHost(id, data, true),
    onMutate: () => {
      // Step 0: Server processing (DB save, nginx deferred to regenerate)
      setSaveProgress((prev) => ({ ...prev, currentStep: 0 }))
    },
    onSuccess: async (_, variables) => {
      // Step 1: Additional settings
      setSaveProgress((prev) => ({ ...prev, currentStep: 1 }))

      if (variables.data.proxy_type !== 'stream') {
        await extras.saveExtrasForUpdate({
          hostId: variables.id,
          botFilterData: state.botFilterData,
          geoData: state.geoData,
          blockedCloudProviders: state.blockedCloudProviders,
          cloudProviderChallengeMode: state.cloudProviderChallengeMode,
          cloudProviderAllowSearchBots: state.cloudProviderAllowSearchBots,
          existingGeoRestriction: state.existingGeoRestriction,
        })
      }

      // Single nginx config generation + test + reload (all settings applied at once)
      try {
        await regenerateHostConfig(variables.id)
      } catch (err) {
        setSaveProgress((prev) => ({
          ...prev,
          ...errorToProgress(err, 'Failed to apply nginx config'),
        }))
        return
      }

      // Step 2: Complete
      setSaveProgress((prev) => ({ ...prev, currentStep: 2 }))
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
      closeProgressWithDelay()
    },
    onError: (error) => {
      setSaveProgress((prev) => ({
        ...prev,
        ...errorToProgress(error, 'Failed to update proxy host'),
      }))
    },
  })

  const mutation = isEditing ? updateMutation : createMutation

  // ───── Submit handler ──────────────────────────────────────────────
  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()

    // Step 0: Validation — open modal first, close on early return
    setSaveProgress({ isOpen: true, currentStep: 0, error: null, errorDetails: null })

    const newErrors = validateProxyHostForm({
      formData: state.formData,
      portInput: state.portInput,
      certMode: state.certMode,
      t,
    })
    state.setErrors(newErrors)
    if (!isFormValid(newErrors)) {
      setSaveProgress(INITIAL_PROGRESS)
      return
    }

    const domains = normalizeDomains(state.formData.domain_names)
    let certificateId = state.formData.certificate_id

    // Step 1: Create certificate if SSL + create mode
    if (!isStreamMode && state.formData.ssl_enabled && state.certMode === 'create') {
      if (domains.length === 0) {
        state.setErrors({ domain_names: t('validation.addDomainsBeforeCert') })
        setSaveProgress(INITIAL_PROGRESS)
        return
      }

      // Close save progress modal while cert is being created (cert has its own UI).
      setSaveProgress(INITIAL_PROGRESS)

      const result = await cert.ensureCertificate(domains, state.newCertData)
      if (!result.ok) {
        // ensureCertificate already handled UI state; don't reset cert modal here.
        return
      }
      certificateId = result.certificateId

      // Re-open save progress modal after cert is created
      setSaveProgress({ isOpen: true, currentStep: 0, error: null, errorDetails: null })
    }

    // Step 2+: Fire the host mutation
    const data: CreateProxyHostRequest = {
      ...state.formData,
      domain_names: domains,
      forward_port: parseInt(state.portInput) || 80,
      certificate_id: certificateId,
    }

    if (data.proxy_type === 'stream') {
      const protocol = data.stream_protocol || 'tcp'
      data.forward_scheme = protocol
      // Stream TLS termination (ssl_enabled + certificate) is allowed for TCP and
      // is mutually exclusive with passthrough (ssl_preread); preserve it. The
      // other SSL flags are HTTP-only and stay off. (#156)
      const isStreamTerminate = !!data.ssl_enabled && !!data.certificate_id && protocol !== 'udp' && !data.stream_ssl_preread
      data.ssl_enabled = isStreamTerminate
      data.ssl_force_https = false
      data.ssl_http2 = false
      data.ssl_http3 = false
      if (!isStreamTerminate) data.certificate_id = undefined
      data.allow_websocket_upgrade = false
      data.cache_enabled = false
      data.block_exploits = false
      data.waf_enabled = false
      data.access_list_id = undefined
      if (protocol === 'udp') {
        data.stream_ssl_preread = false
        data.stream_accept_proxy_protocol = false
        data.stream_send_proxy_protocol = false
      }
    }

    if (isEditing && host) {
      // Manual edit of forward_host clears forward_container_name/network in
      // form state (sets them to undefined). JSON.stringify omits undefined →
      // backend's pointer-merge treats omitted as "no change", so the reconcile
      // scheduler keeps overriding the user's manually-typed IP. Send explicit
      // "" instead so the backend's "*req == "" → clear" semantic fires. Safe
      // no-op when the host never had a container binding. (#151)
      data.forward_container_name = data.forward_container_name ?? ''
      data.forward_container_network = data.forward_container_network ?? ''
      updateMutation.mutate({ id: host.id, data })
    } else {
      createMutation.mutate(data)
    }

    cert.setCertCreating(false)
  }

  /** Close the save-progress modal (e.g. when the user dismisses an error). */
  function closeSaveProgress() {
    setSaveProgress(INITIAL_PROGRESS)
  }

  return {
    saveProgress,
    closeSaveProgress,
    handleSubmit,
    mutation,
  }
}

/** Public return type, inferred. */
export type ProxyHostSubmit = ReturnType<typeof useProxyHostSubmit>

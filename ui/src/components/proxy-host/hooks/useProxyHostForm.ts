import type { ProxyHost } from '../../../types/proxy-host'
import { useProxyHostFormState } from './useProxyHostFormState'
import { useProxyHostCertificate } from './useProxyHostCertificate'
import { useProxyHostExtras } from './useProxyHostExtras'
import { useProxyHostSubmit } from './useProxyHostSubmit'

/**
 * Thin container hook that composes the proxy-host form from four
 * focused sub-hooks:
 *
 *  - {@link useProxyHostFormState}  – field values, setters, queries
 *  - {@link useProxyHostCertificate} – cert create + 2s polling
 *  - {@link useProxyHostExtras}     – bot/geo/cloud saves (skip_reload)
 *  - {@link useProxyHostSubmit}     – 6-step orchestrator
 *
 * The public API matches the original monolithic hook so
 * `ProxyHostForm.tsx` does not need to change.
 */
export function useProxyHostForm(host: ProxyHost | null | undefined, onClose: () => void) {
  const state = useProxyHostFormState(host)
  const cert = useProxyHostCertificate()
  const extras = useProxyHostExtras()
  const submit = useProxyHostSubmit({ host, state, cert, extras, onClose })

  // Domain list helpers — small inline operations on formData.domain_names
  const addDomain = () => {
    state.setFormData((prev) => ({
      ...prev,
      domain_names: [...prev.domain_names, ''],
    }))
  }

  const removeDomain = (index: number) => {
    state.setFormData((prev) => ({
      ...prev,
      domain_names: prev.domain_names.filter((_, i) => i !== index),
    }))
  }

  const updateDomain = (index: number, value: string) => {
    state.setFormData((prev) => ({
      ...prev,
      domain_names: prev.domain_names.map((d, i) => (i === index ? value : d)),
    }))
  }

  const certState = cert.buildCertState(state.certMode, state.newCertData)

  return {
    // Form data + errors
    formData: state.formData,
    setFormData: state.setFormData,
    portInput: state.portInput,
    setPortInput: state.setPortInput,
    errors: state.errors,
    setErrors: state.setErrors,
    isEditing: state.isEditing,

    // Certificate form + creation
    certState,
    setCertMode: state.setCertMode,
    setNewCertData: state.setNewCertData,
    certCreating: cert.certCreating,
    pendingCertId: cert.pendingCertId,
    closeCertLogModal: cert.closeCertLogModal,

    // Bot filter
    botFilterData: state.botFilterData,
    setBotFilterData: state.setBotFilterData,

    // GeoIP
    geoData: state.geoData,
    setGeoData: state.setGeoData,
    geoSearchTerm: state.geoSearchTerm,
    setGeoSearchTerm: state.setGeoSearchTerm,
    allowedIPsInput: state.allowedIPsInput,
    setAllowedIPsInput: state.setAllowedIPsInput,

    // Cloud provider blocking
    blockedCloudProviders: state.blockedCloudProviders,
    setBlockedCloudProviders: state.setBlockedCloudProviders,
    cloudProviderChallengeMode: state.cloudProviderChallengeMode,
    setCloudProviderChallengeMode: state.setCloudProviderChallengeMode,
    cloudProviderAllowSearchBots: state.cloudProviderAllowSearchBots,
    setCloudProviderAllowSearchBots: state.setCloudProviderAllowSearchBots,

    // External data
    availableCerts: state.availableCerts,
    pendingCerts: state.pendingCerts,
    availableAccessLists: state.availableAccessLists,
    dnsProviders: state.dnsProviders,
    geoipStatus: state.geoipStatus,
    countryCodes: state.countryCodes,

    // Submit + progress
    mutation: submit.mutation,
    saveProgress: submit.saveProgress,
    closeSaveProgress: submit.closeSaveProgress,
    handleSubmit: submit.handleSubmit,

    // Domain helpers
    addDomain,
    removeDomain,
    updateDomain,
  }
}

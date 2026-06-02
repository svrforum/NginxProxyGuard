import type { CreateProxyHostRequest } from '../../../types/proxy-host'
import type { FormErrors } from '../types'

const ipv4AddressPattern =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const ipv6AddressPattern = /^\[?[0-9a-fA-F:]+\]?$/

function isValidStreamListenHost(host: string | undefined): boolean {
  const value = (host || '').trim()
  if (!value || value === '*' || value === '0.0.0.0' || value === '::') {
    return true
  }
  return ipv4AddressPattern.test(value) || (value.includes(':') && ipv6AddressPattern.test(value))
}

/**
 * Arguments required to validate a proxy host form.
 */
export interface ProxyHostValidationInput {
  formData: CreateProxyHostRequest
  portInput: string
  certMode: 'select' | 'create'
  /**
   * i18n translator scoped to the `proxyHost` namespace.
   * Accepting a callable keeps this module free of any React dependency.
   */
  t: (key: string) => string
}

/**
 * Validate the core proxy host form fields (domains, forward host/port,
 * certificate selection when SSL is on). Returns a FormErrors map — empty
 * object means the form is valid.
 *
 * Pure function — no React state, no hooks.
 */
export function validateProxyHostForm({
  formData,
  portInput,
  certMode,
  t,
}: ProxyHostValidationInput): FormErrors {
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

  if (formData.proxy_type === 'stream') {
    if (!isValidStreamListenHost(formData.stream_listen_host)) {
      newErrors.stream_listen_host = t('validation.streamListenHostInvalid')
    }

    const listenPort = Number(formData.stream_listen_port || 0)
    if (!listenPort || listenPort < 1 || listenPort > 65535) {
      newErrors.stream_listen_port = t('validation.portRange')
    }

    // Stream TLS termination reuses ssl_enabled + certificate_id and requires
    // a certificate (selected via the Basic tab dropdown; no create-mode here).
    if (formData.ssl_enabled && !formData.certificate_id) {
      newErrors.certificate_id = t('validation.certSelectionRequired')
    }
  }

  if (formData.proxy_type !== 'stream' && formData.ssl_enabled && certMode === 'select' && !formData.certificate_id) {
    newErrors.certificate_id = t('validation.certSelectionRequired')
  }

  return newErrors
}

/**
 * Convenience helper: returns `true` when the provided errors object is empty.
 */
export function isFormValid(errors: FormErrors): boolean {
  return Object.keys(errors).length === 0
}

/**
 * Normalize domain_names: trim whitespace and drop empty entries.
 * Used in both validation and submit flows — extracted to keep behavior
 * consistent across callers.
 */
export function normalizeDomains(domainNames: string[]): string[] {
  return domainNames.map((d) => d.trim()).filter((d) => d)
}

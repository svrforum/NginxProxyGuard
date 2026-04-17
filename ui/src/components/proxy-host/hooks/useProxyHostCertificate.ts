import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { createCertificate, getCertificate } from '../../../api/certificates'
import type { CreateCertificateRequest } from '../../../types/certificate'
import type { CertificateState } from '../types'

/**
 * Default max wait time for certificate polling (2 minutes).
 * Matches the original hook's `waitForCertificate(_, 120000)`.
 */
const DEFAULT_POLL_TIMEOUT_MS = 120_000

/** Interval between certificate status polls (2 seconds). */
const POLL_INTERVAL_MS = 2_000

/**
 * Return from {@link useProxyHostCertificate.ensureCertificate}.
 *
 * `ok === false` means the caller should NOT proceed to save the
 * proxy host (either creation failed or polling timed out / errored).
 * The cert log modal is left open so the user can see the error.
 */
export interface EnsureCertificateResult {
  ok: boolean
  certificateId?: string
}

/**
 * Hook for managing the certificate selection/creation UI and the
 * "create a new certificate before saving" sub-flow used by the submit
 * orchestrator.
 *
 * Responsibilities:
 *  - Own UI state for cert creation (progress, error, success, elapsed
 *    time, pending cert id for the log modal).
 *  - Expose {@link ensureCertificate} which creates a cert, polls it
 *    to `issued`, and returns the resulting id.
 */
export function useProxyHostCertificate() {
  const queryClient = useQueryClient()

  const [certCreating, setCertCreating] = useState(false)
  const [certError, setCertError] = useState<string | null>(null)
  const [certSuccess, setCertSuccess] = useState<string | null>(null)
  const [certProgress, setCertProgress] = useState<string | null>(null)
  const [certElapsedTime, setCertElapsedTime] = useState(0)
  /** Id of the pending cert — drives the log modal visibility. */
  const [pendingCertId, setPendingCertId] = useState<string | null>(null)

  /**
   * Poll the certificate's status until it's `issued`, `error`, or the
   * timeout is reached. Updates progress/error state in place so the UI
   * can reflect the current status.
   *
   * @returns true if the certificate reached `issued`, false otherwise.
   */
  async function waitForCertificate(
    certId: string,
    maxWaitTime = DEFAULT_POLL_TIMEOUT_MS,
  ): Promise<boolean> {
    const startTime = Date.now()

    while (Date.now() - startTime < maxWaitTime) {
      const elapsed = Math.floor((Date.now() - startTime) / 1000)
      setCertElapsedTime(elapsed)

      try {
        const cert = await getCertificate(certId)

        // Null check for certificate response
        if (!cert) {
          console.error('Certificate not found:', certId)
          setCertProgress(`Issuing certificate... (${elapsed}s)`)
          await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS))
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

      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS))
    }

    setCertError('Certificate issuance timed out. Please check the certificate status manually.')
    return false
  }

  /**
   * Create a certificate for the given domains and wait for it to be
   * issued (if it didn't complete synchronously). Keeps the cert log
   * modal open on failure so the user can see what happened.
   */
  async function ensureCertificate(
    domains: string[],
    newCertData: CreateCertificateRequest,
  ): Promise<EnsureCertificateResult> {
    setCertCreating(true)
    setCertError(null)
    setCertSuccess(null)
    setCertProgress('Creating certificate request...')
    setCertElapsedTime(0)

    try {
      const certData: CreateCertificateRequest = {
        ...newCertData,
        domain_names: domains,
      }
      const cert = await createCertificate(certData)
      setPendingCertId(cert.id) // Open log modal
      queryClient.invalidateQueries({ queryKey: ['certificates'] })

      if (cert.status === 'issued') {
        setCertSuccess('Certificate created!')
        setPendingCertId(null) // Close log modal on success
      } else {
        setCertProgress('Waiting for certificate issuance...')
        const success = await waitForCertificate(cert.id)

        if (!success) {
          setCertCreating(false)
          // DON'T close the modal here - let user see the error.
          // Modal will be closed when user clicks close button.
          return { ok: false }
        }

        setCertSuccess('Certificate issued successfully!')
        setPendingCertId(null) // Close log modal on success
      }

      setCertProgress(null)
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      return { ok: true, certificateId: cert.id }
    } catch (err) {
      setCertError(err instanceof Error ? err.message : 'Failed to create certificate')
      setCertCreating(false)
      // DON'T close the modal here - let user see the error.
      return { ok: false }
    }
  }

  /** Close the certificate log modal. */
  function closeCertLogModal() {
    setPendingCertId(null)
  }

  /** Build the aggregated CertificateState object expected by SSLTabContent. */
  function buildCertState(
    mode: 'select' | 'create',
    newCertData: CreateCertificateRequest,
  ): CertificateState {
    return {
      mode,
      data: newCertData,
      creating: certCreating,
      error: certError,
      success: certSuccess,
      progress: certProgress,
      elapsedTime: certElapsedTime,
    }
  }

  return {
    // Raw state (useful for submit orchestrator)
    certCreating,
    setCertCreating,
    certError,
    certSuccess,
    certProgress,
    certElapsedTime,
    pendingCertId,

    // Derived + handlers
    buildCertState,
    ensureCertificate,
    waitForCertificate,
    closeCertLogModal,
  }
}

/** Public return type, inferred. */
export type ProxyHostCertificate = ReturnType<typeof useProxyHostCertificate>

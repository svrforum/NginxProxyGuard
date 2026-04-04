import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useEscapeKey } from '../hooks/useEscapeKey'
import { getCertificateLogs } from '../api/certificates'
import type { CertificateLog, CertificateLogResponse } from '../types/certificate'

interface CertificateLogModalProps {
  isOpen?: boolean
  certificateId: string | null
  onClose: () => void
  onComplete?: (success: boolean) => void
  title?: string
  subtitle?: string
}

export function CertificateLogModal({ isOpen = true, certificateId, onClose, onComplete, title, subtitle }: CertificateLogModalProps) {
  const { t } = useTranslation(['common', 'certificates'])
  const [logs, setLogs] = useState<CertificateLog[]>([])
  const [status, setStatus] = useState<string>('pending')
  const [isComplete, setIsComplete] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const logContainerRef = useRef<HTMLDivElement>(null)
  const pollIntervalRef = useRef<number | null>(null)

  // Allow ESC to close when complete or error
  useEscapeKey(() => {
    if (isComplete || error) {
      onClose()
    }
  }, isOpen && (isComplete || !!error))

  // Poll for logs
  useEffect(() => {
    if (!isOpen || !certificateId) {
      setLogs([])
      setStatus('pending')
      setIsComplete(false)
      setError(null)
      return
    }

    const fetchLogs = async () => {
      try {
        const response: CertificateLogResponse = await getCertificateLogs(certificateId)
        setLogs(response.logs || [])
        setStatus(response.status)
        setIsComplete(response.is_complete)

        if (response.is_complete) {
          // Stop polling when complete
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
          }
          // Notify parent
          onComplete?.(response.status === 'issued')
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch logs')
      }
    }

    // Initial fetch
    fetchLogs()

    // Start polling every 3 seconds
    pollIntervalRef.current = window.setInterval(fetchLogs, 3000)

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }
    }
  }, [isOpen, certificateId, onComplete])

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs])

  if (!isOpen) return null

  const getLogLevelStyles = (level: string) => {
    switch (level) {
      case 'success':
        return 'text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20'
      case 'error':
        return 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20'
      case 'warn':
        return 'text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20'
      default:
        return 'text-slate-600 dark:text-slate-400'
    }
  }

  const getLogLevelIcon = (level: string) => {
    switch (level) {
      case 'success':
        return (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        )
      case 'error':
        return (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        )
      case 'warn':
        return (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        )
      default:
        return (
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        )
    }
  }

  const getStatusBadge = () => {
    switch (status) {
      case 'issued':
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">
            {t('certificates:status.issued', 'Issued')}
          </span>
        )
      case 'error':
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">
            {t('certificates:status.error', 'Error')}
          </span>
        )
      case 'pending':
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300 flex items-center gap-1">
            <div className="w-3 h-3 rounded-full border-2 border-amber-500 border-t-transparent animate-spin" />
            {t('certificates:status.pending', 'In Progress')}
          </span>
        )
      default:
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300">
            {status}
          </span>
        )
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary-100 dark:bg-primary-900/30 flex items-center justify-center">
                <svg className="w-5 h-5 text-primary-600 dark:text-primary-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                  {title || t('certificates:issuance.title', 'Certificate Issuance')}
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  {subtitle || t('certificates:issuance.subtitle', 'Real-time progress log')}
                </p>
              </div>
            </div>
            {getStatusBadge()}
          </div>
        </div>

        {/* Log Container */}
        <div
          ref={logContainerRef}
          className="flex-1 overflow-y-auto p-4 space-y-2 bg-slate-50 dark:bg-slate-900/50 font-mono text-sm min-h-[300px]"
        >
          {logs.length === 0 && !error && (
            <div className="flex items-center justify-center h-full text-slate-500 dark:text-slate-400">
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-2 rounded-full border-2 border-primary-500 border-t-transparent animate-spin" />
                <p>{t('certificates:issuance.waiting', 'Waiting for logs...')}</p>
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">
              <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>{error}</span>
            </div>
          )}

          {logs.map((log, index) => (
            <div
              key={index}
              className={`flex items-start gap-2 p-2 rounded ${getLogLevelStyles(log.level)}`}
            >
              <span className="flex-shrink-0 mt-0.5">{getLogLevelIcon(log.level)}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 mb-0.5">
                  <span>{new Date(log.timestamp).toLocaleTimeString()}</span>
                  {log.step && (
                    <span className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                      {log.step}
                    </span>
                  )}
                </div>
                <p className="break-words">{log.message}</p>
              </div>
            </div>
          ))}

          {/* Show spinner at the end while still pending */}
          {!isComplete && logs.length > 0 && (
            <div className="flex items-center gap-2 p-2 text-slate-500 dark:text-slate-400">
              <div className="w-4 h-4 rounded-full border-2 border-slate-400 border-t-transparent animate-spin" />
              <span className="text-xs">{t('certificates:issuance.processing', 'Processing...')}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 flex-shrink-0">
          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {isComplete
                ? t('certificates:issuance.completed', 'Certificate issuance completed')
                : t('certificates:issuance.inProgress', 'Certificate issuance in progress...')
              }
            </p>
            <button
              onClick={onClose}
              disabled={!isComplete && !error}
              className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                isComplete || error
                  ? status === 'issued'
                    ? 'bg-green-600 hover:bg-green-700 text-white'
                    : status === 'error' || error
                    ? 'bg-red-600 hover:bg-red-700 text-white'
                    : 'bg-primary-600 hover:bg-primary-700 text-white'
                  : 'bg-slate-200 dark:bg-slate-700 text-slate-400 cursor-not-allowed'
              }`}
            >
              {isComplete || error ? t('common:buttons.close') : t('certificates:issuance.pleaseWait', 'Please wait...')}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

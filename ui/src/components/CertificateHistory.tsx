import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { getCertificateHistory } from '../api/certificates'
import { ModalShell } from './common/ModalShell'
import { EntityCard, EmptyState, IconButton, EyeIcon } from './common/listui'
import type { CertificateHistory, CertificateLog } from '../types/certificate'

interface CertificateHistoryLogModalProps {
  isOpen: boolean
  history: CertificateHistory | null
  onClose: () => void
}

function HistoryLogModal({ isOpen, history, onClose }: CertificateHistoryLogModalProps) {
  const { t } = useTranslation(['common', 'certificates'])

  if (!history) return null

  let logs: CertificateLog[] = []
  try {
    if (history.logs) {
      logs = JSON.parse(history.logs)
    }
  } catch {
    // Invalid JSON, ignore
  }

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

  return (
    <ModalShell isOpen={isOpen} onClose={onClose} panelClassName="max-w-2xl" labelledById="certificate-history-log-title">
      <div className="flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                history.status === 'success'
                  ? 'bg-green-100 dark:bg-green-900/30'
                  : 'bg-red-100 dark:bg-red-900/30'
              }`}>
                <svg className={`w-5 h-5 ${
                  history.status === 'success'
                    ? 'text-green-600 dark:text-green-400'
                    : 'text-red-600 dark:text-red-400'
                }`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h3 id="certificate-history-log-title" className="text-lg font-semibold text-slate-900 dark:text-white">
                  {t('certificates:history.logTitle', 'Operation Log')}
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  {history.domain_names.join(', ')}
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              aria-label={t('common:buttons.close')}
              className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Log Container */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2 bg-slate-50 dark:bg-slate-900/50 font-mono text-sm min-h-[200px]">
          {logs.length === 0 ? (
            <div className="flex items-center justify-center h-full text-slate-500 dark:text-slate-400">
              <p>{t('certificates:history.noLogs', 'No detailed logs available')}</p>
            </div>
          ) : (
            logs.map((log, index) => (
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
            ))
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 flex-shrink-0">
          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {new Date(history.created_at).toLocaleString()}
            </p>
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium rounded-lg bg-primary-600 hover:bg-primary-700 text-white transition-colors"
            >
              {t('common:buttons.close')}
            </button>
          </div>
        </div>
      </div>
    </ModalShell>
  )
}

export default function CertificateHistoryList() {
  const { t, i18n } = useTranslation(['common', 'certificates'])
  const [page, setPage] = useState(1)
  const [selectedHistory, setSelectedHistory] = useState<CertificateHistory | null>(null)
  const perPage = 20

  const { data, isLoading, error } = useQuery({
    queryKey: ['certificate-history', page, perPage],
    queryFn: () => getCertificateHistory(page, perPage),
  })

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString(i18n.language)
  }

  const getActionBadge = (action: string, status: string) => {
    if (status === 'error') {
      return (
        <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300">
          {t('certificates:history.error', 'Error')}
        </span>
      )
    }
    switch (action) {
      case 'issued':
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300">
            {t('certificates:history.issued', 'Issued')}
          </span>
        )
      case 'renewed':
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300">
            {t('certificates:history.renewed', 'Renewed')}
          </span>
        )
      case 'expired':
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300">
            {t('certificates:history.expired', 'Expired')}
          </span>
        )
      default:
        return (
          <span className="px-2 py-1 text-xs font-medium rounded-full bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300">
            {action}
          </span>
        )
    }
  }

  const getProviderBadge = (provider: string) => {
    return (
      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
        provider === 'letsencrypt'
          ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300'
          : provider === 'selfsigned'
          ? 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'
          : 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
      }`}>
        {t(`certificates:certProviders.${provider}`)}
      </span>
    )
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded">
        {t('certificates:messages.loadError')}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
          {t('certificates:history.title', 'Certificate History')}
        </h2>
      </div>

      {data?.data?.length === 0 ? (
        <EmptyState
          icon={
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        >
          {t('certificates:history.empty', 'No certificate history found')}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {data?.data?.map((h: CertificateHistory) => (
            <EntityCard key={h.id}>
              <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
                <div className="flex min-w-0 flex-1 flex-col gap-2">
                  <div className="min-w-0">
                    <span className="block truncate text-sm font-semibold text-slate-900 dark:text-white">
                      {h.domain_names[0]}
                    </span>
                    {h.domain_names.length > 1 && (
                      <span className="block truncate text-xs text-slate-500 dark:text-slate-400">
                        {t('certificates:list.more', { count: h.domain_names.length - 1 })}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {getActionBadge(h.action, h.status)}
                    {getProviderBadge(h.provider)}
                    <span className="text-xs text-slate-400 dark:text-slate-500">
                      {formatDate(h.created_at)}
                    </span>
                  </div>
                  {h.message && (
                    <p className="truncate text-xs text-slate-500 dark:text-slate-400" title={h.message}>
                      {h.message}
                    </p>
                  )}
                </div>

                <IconButton
                  onClick={() => setSelectedHistory(h)}
                  title={t('certificates:history.viewLogs', 'View Logs')}
                >
                  <EyeIcon />
                </IconButton>
              </div>
            </EntityCard>
          ))}
        </div>
      )}

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
          <div className="flex items-center text-sm text-slate-500 dark:text-slate-400">
            {t('common:pagination.showing', 'Showing')} {(page - 1) * perPage + 1} - {Math.min(page * perPage, data.total)} {t('common:pagination.of', 'of')} {data.total}
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(page - 1)}
              disabled={page <= 1}
              className="px-3 py-1 text-sm rounded border border-slate-300 dark:border-slate-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700"
            >
              {t('common:pagination.previous', 'Previous')}
            </button>
            <button
              onClick={() => setPage(page + 1)}
              disabled={page >= data.total_pages}
              className="px-3 py-1 text-sm rounded border border-slate-300 dark:border-slate-600 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-700"
            >
              {t('common:pagination.next', 'Next')}
            </button>
          </div>
        </div>
      )}

      {/* Log Detail Modal */}
      <HistoryLogModal
        isOpen={!!selectedHistory}
        history={selectedHistory}
        onClose={() => setSelectedHistory(null)}
      />
    </div>
  )
}

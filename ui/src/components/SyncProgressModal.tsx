import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useEscapeKey } from '../hooks/useEscapeKey'

export interface SyncHostResult {
  host_id: string
  domain_names: string[]
  success: boolean
  error?: string
}

export interface SyncAllResult {
  total_hosts: number
  success_count: number
  failed_count: number
  hosts: SyncHostResult[]
  test_success: boolean
  test_error?: string
  reload_success: boolean
  reload_error?: string
}

interface SyncProgressModalProps {
  isOpen: boolean
  isLoading: boolean
  result: SyncAllResult | null
  onClose: () => void
}

export function SyncProgressModal({ isOpen, isLoading, result, onClose }: SyncProgressModalProps) {
  const { t } = useTranslation(['common', 'proxyHost'])
  const [expandedErrors, setExpandedErrors] = useState<Set<string>>(new Set())

  useEscapeKey(onClose, isOpen && !isLoading)

  if (!isOpen) return null

  const toggleError = (hostId: string) => {
    setExpandedErrors(prev => {
      const newSet = new Set(prev)
      if (newSet.has(hostId)) {
        newSet.delete(hostId)
      } else {
        newSet.add(hostId)
      }
      return newSet
    })
  }

  const hasErrors = result && (result.failed_count > 0 || !result.test_success || !result.reload_success)
  const isSuccess = result && !hasErrors

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            {t('common:actions.syncAll')}
          </h3>
          {!isLoading && (
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {/* Loading State */}
          {isLoading && (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mb-4" />
              <p className="text-slate-600 dark:text-slate-400">{t('common:sync.syncing')}</p>
            </div>
          )}

          {/* Result State */}
          {result && !isLoading && (
            <div className="space-y-4">
              {/* Summary */}
              <div className={`p-4 rounded-lg ${isSuccess
                ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800'
                : 'bg-red-50 border border-red-200 dark:bg-red-900/20 dark:border-red-800'
              }`}>
                <div className="flex items-center gap-3">
                  {isSuccess ? (
                    <div className="w-10 h-10 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
                      <svg className="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                  ) : (
                    <div className="w-10 h-10 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                      <svg className="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    </div>
                  )}
                  <div>
                    <h4 className={`font-medium ${isSuccess ? 'text-green-800 dark:text-green-300' : 'text-red-800 dark:text-red-300'}`}>
                      {isSuccess ? t('common:sync.success') : t('common:sync.failed')}
                    </h4>
                    <p className={`text-sm ${isSuccess ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                      {!result.test_success
                        ? t('common:sync.testFailed')
                        : !result.reload_success
                          ? t('common:sync.reloadFailed')
                          : t('common:sync.summary', {
                              total: result.total_hosts,
                              success: result.success_count,
                              failed: result.failed_count
                            })
                      }
                    </p>
                  </div>
                </div>
              </div>

              {/* Steps */}
              <div className="space-y-2">
                {/* Config Generation Step */}
                <div className={`flex items-center gap-3 p-3 rounded-lg ${
                  result.failed_count === 0
                    ? 'bg-green-50 dark:bg-green-900/20'
                    : 'bg-red-50 dark:bg-red-900/20'
                }`}>
                  {result.failed_count === 0 ? (
                    <svg className="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  )}
                  <span className={`text-sm font-medium ${
                    result.failed_count === 0
                      ? 'text-green-700 dark:text-green-300'
                      : 'text-red-700 dark:text-red-300'
                  }`}>
                    {t('common:sync.configGeneration')} ({result.success_count}/{result.total_hosts})
                  </span>
                </div>

                {/* Nginx Test Step */}
                <div className={`flex items-center gap-3 p-3 rounded-lg ${
                  result.test_success
                    ? 'bg-green-50 dark:bg-green-900/20'
                    : 'bg-red-50 dark:bg-red-900/20'
                }`}>
                  {result.test_success ? (
                    <svg className="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  )}
                  <span className={`text-sm font-medium ${
                    result.test_success
                      ? 'text-green-700 dark:text-green-300'
                      : 'text-red-700 dark:text-red-300'
                  }`}>
                    {t('common:sync.nginxTest')}
                  </span>
                </div>

                {/* Test Error */}
                {result.test_error && (
                  <div className="ml-8 p-3 bg-slate-900 dark:bg-slate-950 rounded-md">
                    <pre className="text-xs text-red-300 overflow-x-auto whitespace-pre-wrap break-words max-h-32 overflow-y-auto font-mono">
                      {result.test_error}
                    </pre>
                  </div>
                )}

                {/* Nginx Reload Step */}
                <div className={`flex items-center gap-3 p-3 rounded-lg ${
                  result.reload_success
                    ? 'bg-green-50 dark:bg-green-900/20'
                    : result.test_success
                      ? 'bg-red-50 dark:bg-red-900/20'
                      : 'bg-slate-100 dark:bg-slate-700/50'
                }`}>
                  {result.reload_success ? (
                    <svg className="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : result.test_success ? (
                    <svg className="w-5 h-5 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  ) : (
                    <div className="w-5 h-5 rounded-full border-2 border-slate-300 dark:border-slate-600" />
                  )}
                  <span className={`text-sm font-medium ${
                    result.reload_success
                      ? 'text-green-700 dark:text-green-300'
                      : result.test_success
                        ? 'text-red-700 dark:text-red-300'
                        : 'text-slate-400 dark:text-slate-500'
                  }`}>
                    {t('common:sync.nginxReload')}
                  </span>
                </div>

                {/* Reload Error */}
                {result.reload_error && (
                  <div className="ml-8 p-3 bg-slate-900 dark:bg-slate-950 rounded-md">
                    <pre className="text-xs text-red-300 overflow-x-auto whitespace-pre-wrap break-words max-h-32 overflow-y-auto font-mono">
                      {result.reload_error}
                    </pre>
                  </div>
                )}
              </div>

              {/* Host Details */}
              {result.hosts.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('common:sync.hostDetails')}
                  </h4>
                  <div className="space-y-1 max-h-64 overflow-y-auto">
                    {result.hosts.map((host) => (
                      <div key={host.host_id} className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
                        <div
                          className={`flex items-center justify-between p-2 ${
                            host.success
                              ? 'bg-white dark:bg-slate-800'
                              : 'bg-red-50 dark:bg-red-900/20 cursor-pointer'
                          }`}
                          onClick={() => !host.success && toggleError(host.host_id)}
                        >
                          <div className="flex items-center gap-2">
                            {host.success ? (
                              <svg className="w-4 h-4 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                              </svg>
                            ) : (
                              <svg className="w-4 h-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            )}
                            <span className={`text-sm ${host.success ? 'text-slate-700 dark:text-slate-300' : 'text-red-700 dark:text-red-300'}`}>
                              {host.domain_names[0]}
                              {host.domain_names.length > 1 && (
                                <span className="text-slate-400 dark:text-slate-500 ml-1">
                                  +{host.domain_names.length - 1}
                                </span>
                              )}
                            </span>
                          </div>
                          {!host.success && (
                            <svg
                              className={`w-4 h-4 text-slate-400 transition-transform ${expandedErrors.has(host.host_id) ? 'rotate-90' : ''}`}
                              fill="none"
                              stroke="currentColor"
                              viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                          )}
                        </div>
                        {!host.success && expandedErrors.has(host.host_id) && host.error && (
                          <div className="p-2 bg-slate-900 dark:bg-slate-950 border-t border-slate-700">
                            <pre className="text-xs text-red-300 overflow-x-auto whitespace-pre-wrap break-words font-mono">
                              {host.error}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        {!isLoading && (
          <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
            <button
              onClick={onClose}
              className={`w-full px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors ${
                isSuccess
                  ? 'bg-primary-600 hover:bg-primary-700'
                  : 'bg-red-600 hover:bg-red-700'
              }`}
            >
              {t('common:buttons.close')}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

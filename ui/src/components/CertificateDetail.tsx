import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { getCertificate } from '../api/certificates'
import { fetchProxyHosts } from '../api/proxy-hosts'
import { useEscapeKey } from '../hooks/useEscapeKey'
import type { Certificate } from '../types/certificate'

interface CertificateDetailProps {
  certificateId: string
  onClose: () => void
}

export function CertificateDetail({ certificateId, onClose }: CertificateDetailProps) {
  const { t, i18n } = useTranslation('certificates')
  useEscapeKey(onClose)

  const { data: cert, isLoading, error } = useQuery({
    queryKey: ['certificate', certificateId],
    queryFn: () => getCertificate(certificateId),
  })

  const { data: linkedHosts } = useQuery({
    queryKey: ['certificate-linked-hosts', certificateId],
    queryFn: async () => {
      const result = await fetchProxyHosts(1, 100)
      return result.data.filter(h => h.certificate_id === certificateId)
    },
  })

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString(i18n.language)
  }

  const getStatusColor = (status: Certificate['status']) => {
    const colors = {
      pending: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800',
      issued: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 border-green-200 dark:border-green-800',
      expired: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 border-red-200 dark:border-red-800',
      error: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 border-red-200 dark:border-red-800',
      renewing: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 border-blue-200 dark:border-blue-800',
    }
    return colors[status] || 'bg-gray-100 dark:bg-slate-700 text-gray-800 dark:text-slate-300'
  }

  const getProviderInfo = (provider: Certificate['provider']) => {
    const info = {
      letsencrypt: { label: t('form.providers.letsEncrypt'), color: 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300', icon: '🔐' },
      selfsigned: { label: t('form.providers.selfSigned'), color: 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300', icon: '📝' },
      custom: { label: t('form.providers.custom'), color: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300', icon: '📤' },
    }
    return info[provider] || { label: provider, color: 'bg-slate-100 dark:bg-slate-700', icon: '📜' }
  }

  const getDaysColor = (days?: number) => {
    if (days === undefined) return 'text-slate-500 dark:text-slate-400'
    if (days <= 7) return 'text-red-600 dark:text-red-400 font-bold'
    if (days <= 30) return 'text-orange-600 dark:text-orange-400 font-semibold'
    if (days <= 60) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-green-600 dark:text-green-400'
  }

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto border dark:border-slate-700">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <svg className="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              {t('detail.title')}
            </h2>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="p-8 flex justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
          </div>
        ) : error ? (
          <div className="p-6 bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400">
            {t('detail.errorLoad')}
          </div>
        ) : cert ? (
          <div className="p-6 space-y-6">
            {/* Status & Provider */}
            <div className="flex items-center gap-3">
              <span className={`px-3 py-1.5 text-sm font-medium rounded-full border ${getStatusColor(cert.status)}`}>
                {t(`certStatuses.${cert.status}`)}
              </span>
              <span className={`px-3 py-1.5 text-sm font-medium rounded-full ${getProviderInfo(cert.provider).color}`}>
                {getProviderInfo(cert.provider).icon} {getProviderInfo(cert.provider).label}
              </span>
              {cert.auto_renew && (
                <span className="px-3 py-1.5 text-sm font-medium rounded-full bg-cyan-100 text-cyan-800">
                  🔄 {t('detail.autoRenew')}
                </span>
              )}
            </div>

            {/* Domains */}
            <div>
              <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-2">{t('detail.domains')}</h3>
              <div className="flex flex-wrap gap-2">
                {cert.domain_names.map((domain, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1.5 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-mono"
                  >
                    {domain}
                  </span>
                ))}
              </div>
            </div>

            {/* Validity Period */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-slate-50 dark:bg-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">{t('detail.issuedAt')}</h3>
                <p className="text-slate-900 dark:text-white font-medium">{formatDate(cert.issued_at)}</p>
              </div>
              <div className="bg-slate-50 dark:bg-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">{t('detail.expiresAt')}</h3>
                <p className="text-slate-900 dark:text-white font-medium">{formatDate(cert.expires_at)}</p>
              </div>
            </div>

            {/* Days Until Expiry */}
            {cert.days_until_expiry !== undefined && (
              <div className="bg-gradient-to-r from-slate-50 to-slate-100 dark:from-slate-700/50 dark:to-slate-700/30 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400">{t('detail.timeUntilExpiry')}</h3>
                  <span className={`text-2xl font-bold ${getDaysColor(cert.days_until_expiry)}`}>
                    {t('list.days', { count: cert.days_until_expiry })}
                  </span>
                </div>
                {/* Progress bar */}
                <div className="mt-3 h-2 bg-slate-200 dark:bg-slate-600 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${cert.days_until_expiry <= 7 ? 'bg-red-500' :
                      cert.days_until_expiry <= 30 ? 'bg-orange-500' :
                        cert.days_until_expiry <= 60 ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                    style={{ width: `${Math.min(100, (cert.days_until_expiry / 90) * 100)}%` }}
                  />
                </div>
                {cert.needs_renewal && (
                  <p className="mt-2 text-sm text-orange-600 flex items-center gap-1">
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                    {t('detail.needsRenewal')}
                  </p>
                )}
              </div>
            )}

            {/* DNS Provider */}
            {cert.dns_provider && (
              <div>
                <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-2">{t('detail.dnsProvider')}</h3>
                <div className="bg-slate-50 dark:bg-slate-700/50 rounded-lg p-4 flex items-center gap-3">
                  <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900/30 rounded-lg flex items-center justify-center">
                    <svg className="w-6 h-6 text-orange-600 dark:text-orange-400" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
                    </svg>
                  </div>
                  <div>
                    <p className="font-medium text-slate-900 dark:text-white">{cert.dns_provider.name}</p>
                    <p className="text-sm text-slate-500 dark:text-slate-400 capitalize">{cert.dns_provider.provider_type}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Certificate Paths */}
            <div>
              <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-2">{t('detail.files')}</h3>
              <div className="bg-slate-900 dark:bg-slate-950 rounded-lg p-4 font-mono text-sm space-y-2">
                <div className="flex items-start gap-2">
                  <span className="text-green-400">cert:</span>
                  <span className="text-slate-300 break-all">{cert.certificate_path}</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="text-yellow-400">key:</span>
                  <span className="text-slate-300 break-all">{cert.private_key_path}</span>
                </div>
              </div>
            </div>

            {/* Linked Hosts */}
            <div>
              <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-2">{t('detail.linkedHosts')}</h3>
              {linkedHosts && linkedHosts.length > 0 ? (
                <div className="space-y-2">
                  {linkedHosts.map(host => (
                    <div key={host.id} className="flex items-center gap-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg p-3">
                      <div className={`w-2 h-2 rounded-full ${host.enabled ? 'bg-green-500' : 'bg-slate-400'}`} />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                          {host.domain_names[0]}
                        </p>
                        {host.domain_names.length > 1 && (
                          <p className="text-xs text-slate-500 dark:text-slate-400">
                            +{host.domain_names.length - 1} more
                          </p>
                        )}
                      </div>
                      <span className="text-xs text-slate-500 dark:text-slate-400">
                        → {host.forward_scheme}://{host.forward_host}:{host.forward_port}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400 dark:text-slate-500 italic">{t('detail.noLinkedHosts')}</p>
              )}
            </div>

            {/* Error Message */}
            {cert.error_message && (
              <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4">
                <h3 className="text-sm font-medium text-red-800 dark:text-red-300 mb-1 flex items-center gap-2">
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  {t('list.error')}
                </h3>
                <p className="text-sm text-red-700 dark:text-red-400">{cert.error_message}</p>
              </div>
            )}

            {/* Metadata */}
            <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
              <div className="grid grid-cols-2 gap-4 text-sm text-slate-500 dark:text-slate-400">
                <div>
                  <span className="font-medium">{t('detail.id')}</span>{' '}
                  <code className="text-xs bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded">{cert.id}</code>
                </div>
                <div>
                  <span className="font-medium">{t('detail.created')}</span> {formatDate(cert.created_at)}
                </div>
              </div>
            </div>
          </div>
        ) : null}

        <div className="p-4 border-t border-slate-200 dark:border-slate-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors"
          >
            {t('detail.close')}
          </button>
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { importDDNSFromHosts } from '../../api/ddns'
import { fetchProxyHosts } from '../../api/proxy-hosts'
import { listDNSProviders } from '../../api/dns-providers'
import { useEscapeKey } from '../../hooks/useEscapeKey'
import type { DNSProvider } from '../../types/certificate'

interface DDNSImportFromHostsModalProps {
  onClose: () => void
  onSuccess: () => void
}

// DDNS only supports providers whose A record can be updated programmatically.
const SUPPORTED_PROVIDER_TYPES: DNSProvider['provider_type'][] = ['cloudflare', 'duckdns', 'dynu']

export default function DDNSImportFromHostsModal({ onClose, onSuccess }: DDNSImportFromHostsModalProps) {
  const { t } = useTranslation('ddns')

  useEscapeKey(onClose)

  const [selectedHostIds, setSelectedHostIds] = useState<string[]>([])
  const [dnsProviderId, setDnsProviderId] = useState('')
  const [error, setError] = useState('')

  // Fetch up to 100 proxy hosts for selection (existing proxy-hosts API).
  const { data: hostsData, isLoading: hostsLoading } = useQuery({
    queryKey: ['proxy-hosts', 'ddns-import'],
    queryFn: () => fetchProxyHosts(1, 100),
  })

  const { data: providersData } = useQuery({
    queryKey: ['dns-providers'],
    queryFn: () => listDNSProviders(),
  })

  const supportedProviders = (providersData?.data ?? []).filter((p) =>
    SUPPORTED_PROVIDER_TYPES.includes(p.provider_type)
  )

  const importMutation = useMutation({
    mutationFn: () => importDDNSFromHosts(selectedHostIds, dnsProviderId),
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  })

  const toggleHost = (id: string) => {
    setSelectedHostIds((prev) =>
      prev.includes(id) ? prev.filter((h) => h !== id) : [...prev, id]
    )
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (selectedHostIds.length === 0) {
      setError(t('importNoHostsSelected'))
      return
    }
    if (!dnsProviderId) {
      setError(t('providerRequired'))
      return
    }
    importMutation.mutate()
  }

  const isPending = importMutation.isPending
  const hosts = hostsData?.data ?? []

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto border dark:border-slate-700">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
              {t('importFromHosts')}
            </h2>
            <button
              onClick={onClose}
              disabled={isPending}
              className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {error && (
            <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400 text-sm">
              {error}
            </div>
          )}

          <p className="text-sm text-slate-600 dark:text-slate-400">{t('importHint')}</p>

          {/* Proxy host multi-select */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('selectHosts')}
            </label>
            {hostsLoading ? (
              <div className="flex justify-center items-center h-24">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-indigo-600"></div>
              </div>
            ) : hosts.length === 0 ? (
              <p className="text-sm text-slate-500 dark:text-slate-400 py-4">{t('importNoHosts')}</p>
            ) : (
              <div className="max-h-64 overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-600 divide-y divide-slate-100 dark:divide-slate-700">
                {hosts.map((host) => (
                  <label
                    key={host.id}
                    className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/50"
                  >
                    <input
                      type="checkbox"
                      checked={selectedHostIds.includes(host.id)}
                      onChange={() => toggleHost(host.id)}
                      className="rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                    />
                    <span className="text-sm text-slate-700 dark:text-slate-300 truncate">
                      {host.domain_names.join(', ')}
                    </span>
                    {host.ddns_enabled && (
                      <span className="ml-auto px-2 py-0.5 text-xs font-medium rounded-full bg-cyan-100 dark:bg-cyan-900/30 text-cyan-800 dark:text-cyan-300">
                        {t('ddnsAlreadyEnabled')}
                      </span>
                    )}
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Provider */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('provider')}
            </label>
            <select
              value={dnsProviderId}
              onChange={(e) => setDnsProviderId(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="">{t('selectProvider')}</option>
              {supportedProviders.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.provider_type})
                </option>
              ))}
            </select>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('providerHint')}</p>
            {supportedProviders.length === 0 && (
              <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">{t('noProviders')}</p>
            )}
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={onClose}
              disabled={isPending}
              className="px-4 py-2 text-sm font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
            >
              {t('cancel')}
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              {isPending && (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}
              {t('importAction')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

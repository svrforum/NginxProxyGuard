import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createDDNSRecord, updateDDNSRecord } from '../../api/ddns'
import { listDNSProviders } from '../../api/dns-providers'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../common/HelpTip'
import { useEscapeKey } from '../../hooks/useEscapeKey'
import type { DDNSRecord, CreateDDNSRecordRequest, UpdateDDNSRecordRequest } from '../../types/ddns'
import type { DNSProvider } from '../../types/certificate'

interface DDNSRecordFormProps {
  record?: DDNSRecord | null
  onClose: () => void
  onSuccess: () => void
}

// DDNS only supports providers whose A record can be updated programmatically.
const SUPPORTED_PROVIDER_TYPES: DNSProvider['provider_type'][] = ['cloudflare', 'duckdns']

export default function DDNSRecordForm({ record, onClose, onSuccess }: DDNSRecordFormProps) {
  const { t } = useTranslation('ddns')
  const isEditing = !!record

  useEscapeKey(onClose)

  const [hostname, setHostname] = useState(record?.hostname || '')
  const [dnsProviderId, setDnsProviderId] = useState(record?.dns_provider_id || '')
  const [proxied, setProxied] = useState(record?.proxied ?? false)
  const [ttl, setTtl] = useState(record?.ttl ?? 1)
  const [enabled, setEnabled] = useState(record?.enabled ?? true)
  const [error, setError] = useState('')

  const { data: providersData } = useQuery({
    queryKey: ['dns-providers'],
    queryFn: () => listDNSProviders(),
  })

  const supportedProviders = (providersData?.data ?? []).filter((p) =>
    SUPPORTED_PROVIDER_TYPES.includes(p.provider_type)
  )

  const selectedProvider = supportedProviders.find((p) => p.id === dnsProviderId)
  const isCloudflare = selectedProvider?.provider_type === 'cloudflare'

  const createMutation = useMutation({
    mutationFn: createDDNSRecord,
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateDDNSRecordRequest }) =>
      updateDDNSRecord(id, data),
    onSuccess: () => onSuccess(),
    onError: (err: Error) => setError(err.message),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!hostname.trim()) {
      setError(t('hostnameRequired'))
      return
    }
    if (!dnsProviderId) {
      setError(t('providerRequired'))
      return
    }

    if (isEditing && record) {
      const data: UpdateDDNSRecordRequest = {
        hostname: hostname.trim(),
        dns_provider_id: dnsProviderId,
        proxied,
        ttl,
        enabled,
      }
      updateMutation.mutate({ id: record.id, data })
    } else {
      const data: CreateDDNSRecordRequest = {
        hostname: hostname.trim(),
        dns_provider_id: dnsProviderId,
        proxied,
        ttl,
        enabled,
      }
      createMutation.mutate(data)
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto border dark:border-slate-700">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
              {isEditing ? t('editRecord') : t('addRecord')}
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

          {/* Hostname */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('hostname')}
            </label>
            <input
              type="text"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder={t('hostnamePlaceholder')}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
              required
            />
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

          {/* Record Type (fixed A) */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('recordType')}
            </label>
            <input
              type="text"
              value="A"
              disabled
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm bg-slate-100 dark:bg-slate-900 text-slate-500 dark:text-slate-400 font-mono"
            />
          </div>

          {/* Cloudflare-only: proxied + ttl */}
          {isCloudflare && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
                    {t('proxied')}
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('proxiedDesc')}</p>
                </div>
                <button
                  type="button"
                  onClick={() => setProxied(!proxied)}
                  className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${proxied ? 'bg-primary-600' : 'bg-slate-200 dark:bg-slate-600'}`}
                >
                  <span
                    className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${proxied ? 'translate-x-5' : 'translate-x-0'}`}
                  />
                </button>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('ttl')}
                  <HelpTip content={t('ttlDesc')} />
                </label>
                <input
                  type="number"
                  min={1}
                  value={ttl}
                  onChange={(e) => setTtl(Number(e.target.value) || 1)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                />
              </div>
            </div>
          )}

          {/* Enabled Toggle */}
          <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl border border-transparent dark:border-slate-700">
            <div>
              <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('enabled')}</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('enabledDesc')}</p>
            </div>
            <button
              type="button"
              onClick={() => setEnabled(!enabled)}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${enabled ? 'bg-primary-600' : 'bg-slate-200 dark:bg-slate-600'}`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${enabled ? 'translate-x-5' : 'translate-x-0'}`}
              />
            </button>
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
              {isEditing ? t('update') : t('create')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

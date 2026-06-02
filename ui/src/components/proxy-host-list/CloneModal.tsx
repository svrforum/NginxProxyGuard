import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { listCertificates } from '../../api/certificates'
import { listDNSProviders } from '../../api/dns-providers'
import type { ProxyHost } from '../../types/proxy-host'
import { DockerContainerSelector } from '../proxy-host/DockerContainerSelector'

interface CloneModalProps {
  host: ProxyHost
  isPending: boolean
  isError: boolean
  error: Error | null
  onClone: (params: {
    domainNames: string[]
    certificateId?: string
    certProvider?: string
    dnsProviderId?: string
    forwardScheme: string
    forwardHost: string
    forwardPort: number
    forwardContainerName?: string
    forwardContainerNetwork?: string
    streamListenHost?: string
    streamListenPort?: number
    streamProtocol?: string
    isCreatingCert: boolean
  }) => void
  onClose: () => void
  // Certificate progress
  certCreating: boolean
  certProgress: string | null
  certElapsedTime: number
  certError: string | null
  certSuccess: boolean
}

export function CloneModal({
  host,
  isPending,
  isError,
  error,
  onClone,
  onClose,
  certCreating,
  certProgress,
  certElapsedTime,
  certError,
  certSuccess,
}: CloneModalProps) {
  const { t } = useTranslation('proxyHost')
  const [cloneDomains, setCloneDomains] = useState('')
  const [cloneCertMode, setCloneCertMode] = useState<'select' | 'create'>('select')
  const [cloneCertificateId, setCloneCertificateId] = useState<string>(host.certificate_id || '')
  const [cloneCertProvider, setCloneCertProvider] = useState<'letsencrypt' | 'selfsigned'>('letsencrypt')
  const [cloneDnsProviderId, setCloneDnsProviderId] = useState<string>('')
  const isStream = host.proxy_type === 'stream'
  const [cloneForwardScheme, setCloneForwardScheme] = useState<string>(isStream ? (host.stream_protocol || 'tcp') : host.forward_scheme)
  const [cloneForwardHost, setCloneForwardHost] = useState(host.forward_host)
  const [cloneForwardPort, setCloneForwardPort] = useState(String(host.forward_port))
  const [cloneContainerName, setCloneContainerName] = useState<string>(host.forward_container_name || '')
  const [cloneContainerNetwork, setCloneContainerNetwork] = useState<string>(host.forward_container_network || '')
  const [dockerSelectorOpen, setDockerSelectorOpen] = useState(false)
  const [cloneStreamListenHost, setCloneStreamListenHost] = useState(host.stream_listen_host || '')
  const [cloneStreamListenPort, setCloneStreamListenPort] = useState(String(host.stream_listen_port || ''))

  const { data: certificatesData } = useQuery({
    queryKey: ['certificates-for-clone'],
    queryFn: () => listCertificates(1, 100),
  })

  const { data: dnsProvidersData } = useQuery({
    queryKey: ['dns-providers-for-clone'],
    queryFn: () => listDNSProviders(1, 100),
    enabled: cloneCertMode === 'create' && cloneCertProvider === 'letsencrypt',
  })

  const handleDockerSelect = (host: string, port: number, containerName: string, containerNetwork: string) => {
    setCloneForwardHost(host)
    setCloneForwardPort(port.toString())
    setCloneContainerName(containerName)
    setCloneContainerNetwork(containerNetwork || '')
  }

  const confirmClone = () => {
    if (!cloneDomains.trim()) return
    const domainNames = cloneDomains.split(/[\s,]+/).map(d => d.trim()).filter(d => d)
    if (domainNames.length === 0) return
    const forwardPort = parseInt(cloneForwardPort, 10)

    let certificateId: string | undefined
    let certProvider: string | undefined
    let dnsProviderId: string | undefined
    const isCreatingCert = !isStream && cloneCertMode === 'create'

    if (isStream) {
      certificateId = undefined
    } else if (cloneCertMode === 'select') {
      certificateId = cloneCertificateId || undefined
    } else {
      certProvider = cloneCertProvider
      if (cloneCertProvider === 'letsencrypt' && cloneDnsProviderId) {
        dnsProviderId = cloneDnsProviderId
      }
    }

    onClone({
      domainNames,
      certificateId,
      certProvider,
      dnsProviderId,
      forwardScheme: cloneForwardScheme,
      forwardHost: cloneForwardHost,
      forwardPort: isNaN(forwardPort) ? host.forward_port : forwardPort,
      forwardContainerName: cloneContainerName || undefined,
      forwardContainerNetwork: cloneContainerNetwork || undefined,
      streamListenHost: isStream ? cloneStreamListenHost : undefined,
      streamListenPort: isStream ? parseInt(cloneStreamListenPort, 10) || host.stream_listen_port : undefined,
      streamProtocol: isStream ? cloneForwardScheme : undefined,
      isCreatingCert,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-md overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            {t('actions.cloneTitle')}
          </h3>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('actions.cloneSource')}: {host.domain_names[0]}
          </p>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('actions.cloneDomains')}
            </label>
            <input
              type="text"
              value={cloneDomains}
              onChange={(e) => setCloneDomains(e.target.value)}
              placeholder={t('actions.cloneDomainsPlaceholder')}
              className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('actions.cloneDomainsHelp')}
            </p>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('actions.cloneForwardScheme')}
              </label>
              <select
                value={cloneForwardScheme}
                onChange={(e) => setCloneForwardScheme(e.target.value)}
                className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                {isStream ? (
                  <>
                    <option value="tcp">tcp</option>
                    <option value="udp">udp</option>
                  </>
                ) : (
                  <>
                    <option value="http">http</option>
                    <option value="https">https</option>
                  </>
                )}
              </select>
            </div>
            <div className="col-span-2">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('actions.cloneForwardHost')}
              </label>
              <input
                type="text"
                value={cloneForwardHost}
                onChange={(e) => {
                  setCloneForwardHost(e.target.value)
                  setCloneContainerName('')
                  setCloneContainerNetwork('')
                }}
                placeholder={host.forward_host}
                className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                {t('actions.cloneForwardPort')}
              </label>
              <input
                type="number"
                value={cloneForwardPort}
                onChange={(e) => setCloneForwardPort(e.target.value)}
                placeholder={String(host.forward_port)}
                className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              />
            </div>
          </div>
          <button
            type="button"
            onClick={() => setDockerSelectorOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-primary-700 dark:text-primary-300 bg-primary-50 dark:bg-primary-900/20 hover:bg-primary-100 dark:hover:bg-primary-900/40 rounded-lg transition-colors"
          >
            🐳 {t('actions.cloneBrowseDocker')}
          </button>
          {cloneContainerName && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {t('actions.cloneSelectedContainer')}: <span className="font-mono">{cloneContainerName}</span>
              {cloneContainerNetwork ? ` (${cloneContainerNetwork})` : ''}
            </p>
          )}
          {isStream && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('form.basic.streamListenHost')}
                </label>
                <input
                  type="text"
                  value={cloneStreamListenHost}
                  onChange={(e) => setCloneStreamListenHost(e.target.value)}
                  placeholder="0.0.0.0"
                  className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('form.basic.streamListenPort')}
                </label>
                <input
                  type="number"
                  value={cloneStreamListenPort}
                  onChange={(e) => setCloneStreamListenPort(e.target.value)}
                  placeholder={String(host.stream_listen_port || '')}
                  className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
              </div>
            </div>
          )}
          {/* SSL Certificate Section */}
          {!isStream && <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">
                {t('actions.cloneCertificate')}
              </label>
              <div className="flex gap-1 bg-slate-200 dark:bg-slate-700 rounded-lg p-0.5">
                <button
                  type="button"
                  onClick={() => setCloneCertMode('select')}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${cloneCertMode === 'select' ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'}`}
                >
                  {t('actions.cloneCertExisting')}
                </button>
                <button
                  type="button"
                  onClick={() => setCloneCertMode('create')}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${cloneCertMode === 'create' ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'}`}
                >
                  + {t('actions.cloneCertCreate')}
                </button>
              </div>
            </div>

            {cloneCertMode === 'select' ? (
              <>
                <select
                  value={cloneCertificateId}
                  onChange={(e) => setCloneCertificateId(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  <option value="">{t('actions.cloneCertNone')}</option>
                  {host.certificate_id && (
                    <option value={host.certificate_id}>{t('actions.cloneCertSame')}</option>
                  )}
                  {certificatesData?.data?.filter(cert => cert.status === 'issued' && cert.id !== host.certificate_id).map(cert => (
                    <option key={cert.id} value={cert.id}>
                      {cert.domain_names.join(', ')} ({cert.provider})
                    </option>
                  ))}
                </select>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  {t('actions.cloneCertificateHelp')}
                </p>
              </>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-2">
                    {t('actions.cloneCertProviderLabel')}
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setCloneCertProvider('letsencrypt')}
                      className={`p-3 rounded-lg border-2 text-left transition-colors ${cloneCertProvider === 'letsencrypt'
                        ? 'bg-green-50 border-green-300 dark:bg-green-900/20 dark:border-green-800'
                        : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500'
                        }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-lg">🔐</span>
                        <div>
                          <span className="text-sm font-medium text-slate-900 dark:text-white">Let's Encrypt</span>
                          <p className="text-xs text-slate-500 dark:text-slate-400">{t('actions.cloneCertLetsEncryptDesc')}</p>
                        </div>
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => setCloneCertProvider('selfsigned')}
                      className={`p-3 rounded-lg border-2 text-left transition-colors ${cloneCertProvider === 'selfsigned'
                        ? 'bg-amber-50 border-amber-300 dark:bg-amber-900/20 dark:border-amber-800'
                        : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500'
                        }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-lg">📜</span>
                        <div>
                          <span className="text-sm font-medium text-slate-900 dark:text-white">Self-Signed</span>
                          <p className="text-xs text-slate-500 dark:text-slate-400">{t('actions.cloneCertSelfSignedDesc')}</p>
                        </div>
                      </div>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                    {t('actions.cloneCertDomains')}
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    {cloneDomains.trim() ? (
                      cloneDomains.split(/[\s,]+/).filter(d => d.trim()).map((domain, i) => (
                        <span key={i} className="px-2 py-1 bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 text-xs rounded-full">
                          {domain.trim()}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 dark:text-slate-400 italic">
                        {t('actions.cloneCertDomainsEmpty')}
                      </span>
                    )}
                  </div>
                </div>

                {cloneCertProvider === 'letsencrypt' && (
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                      {t('actions.cloneCertDnsProvider')}
                    </label>
                    <select
                      value={cloneDnsProviderId}
                      onChange={(e) => setCloneDnsProviderId(e.target.value)}
                      className="w-full px-3 py-2 border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                    >
                      <option value="">{t('actions.cloneCertHttpChallenge')}</option>
                      {dnsProvidersData?.data?.map(p => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.provider_type})
                        </option>
                      ))}
                    </select>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {t('actions.cloneCertDnsProviderHelp')}
                    </p>
                  </div>
                )}

                <div className="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg text-sm text-blue-700 dark:text-blue-300 flex items-start gap-2">
                  <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span>
                    {cloneCertProvider === 'letsencrypt'
                      ? t('actions.cloneCertLetsEncryptInfo')
                      : t('actions.cloneCertSelfSignedInfo')}
                  </span>
                </div>
              </div>
            )}
          </div>}
          {isError && !certCreating && (
            <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              {error?.message || t('actions.cloneError')}
            </div>
          )}

          {/* Certificate Progress UI */}
          {(certCreating || certError || certSuccess) && (
            <div className="space-y-3">
              {certCreating && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-600 dark:text-slate-400">
                      {certProgress}
                    </span>
                    <span className="text-slate-500 dark:text-slate-500">
                      {certElapsedTime}s
                    </span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2 overflow-hidden">
                    <div
                      className="h-2 bg-primary-600 rounded-full transition-all duration-1000 animate-pulse"
                      style={{ width: `${Math.min((certElapsedTime / 60) * 100, 95)}%` }}
                    />
                  </div>
                </div>
              )}

              {certError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start gap-2">
                  <svg className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div>
                    <p className="text-sm font-medium text-red-700 dark:text-red-300">
                      {t('actions.cloneCertFailed')}
                    </p>
                    <p className="text-xs text-red-600 dark:text-red-400 mt-0.5">
                      {certError}
                    </p>
                  </div>
                </div>
              )}

              {certSuccess && (
                <div className="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg flex items-center gap-2">
                  <svg className="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <span className="text-sm font-medium text-green-700 dark:text-green-300">
                    {t('actions.cloneCertSuccess')}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
        <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900 flex justify-end gap-3">
          <button
            onClick={onClose}
            disabled={certCreating}
            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors disabled:opacity-50"
          >
            {certSuccess ? t('common:buttons.close') : t('common:buttons.cancel')}
          </button>
          <button
            onClick={confirmClone}
            disabled={isPending || certCreating || certSuccess || !cloneDomains.trim()}
            className="px-4 py-2 text-sm font-medium text-white bg-emerald-600 hover:bg-emerald-700 rounded-lg transition-colors disabled:opacity-50"
          >
            {isPending || certCreating ? t('common:status.processing') : t('actions.clone')}
          </button>
        </div>
      </div>
      <DockerContainerSelector
        isOpen={dockerSelectorOpen}
        onClose={() => setDockerSelectorOpen(false)}
        onSelect={handleDockerSelect}
      />
    </div>
  )
}

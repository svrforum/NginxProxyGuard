import { useState } from 'react'
import type { CreateProxyHostRequest, StreamProtocol } from '../../../types/proxy-host'
import type { FormErrors } from '../types'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../common/HelpTip'
import { DockerContainerSelector } from '../DockerContainerSelector'

interface BasicTabFullProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  portInput: string
  setPortInput: (value: string) => void
  errors: FormErrors
  setErrors: React.Dispatch<React.SetStateAction<FormErrors>>
  addDomain: () => void
  removeDomain: (index: number) => void
  updateDomain: (index: number, value: string) => void
  availableCerts: Array<{
    id: string
    domain_names: string[]
    provider: string
    status: string
  }>
  dnsProviders: Array<{
    id: string
    name: string
    provider_type: string
  }>
}

// DDNS only supports providers whose A record can be updated programmatically.
const DDNS_SUPPORTED_PROVIDER_TYPES = ['cloudflare', 'duckdns']

export function BasicTabContent({
  formData,
  setFormData,
  portInput,
  setPortInput,
  errors,
  setErrors,
  addDomain,
  removeDomain,
  updateDomain,
  availableCerts,
  dnsProviders,
}: BasicTabFullProps) {
  const { t } = useTranslation('proxyHost')
  const [dockerSelectorOpen, setDockerSelectorOpen] = useState(false)
  const isStream = formData.proxy_type === 'stream'
  const streamProtocol = formData.stream_protocol || 'tcp'

  const handleDockerSelect = (host: string, port: number, containerName: string, containerNetwork: string) => {
    // Store the container NAME + NETWORK as the authoritative target (API
    // re-resolves the name to the IP of the picked network, see Issue #151).
    // Pre-fill forward_host with the resolved IP for display.
    setFormData(prev => ({
      ...prev,
      forward_host: host,
      forward_container_name: containerName,
      forward_container_network: containerNetwork || undefined,
    }))
    setPortInput(port.toString())
  }

  const switchProxyType = (proxyType: 'http' | 'stream') => {
    setFormData((prev) => {
      if (proxyType === 'stream') {
        const protocol = prev.stream_protocol || 'tcp'
        return {
          ...prev,
          proxy_type: 'stream',
          forward_scheme: protocol,
          ssl_enabled: false,
          ssl_force_https: false,
          ssl_http2: false,
          ssl_http3: false,
          certificate_id: undefined,
          allow_websocket_upgrade: false,
          cache_enabled: false,
          block_exploits: false,
          waf_enabled: false,
          access_list_id: undefined,
        }
      }
      return {
        ...prev,
        proxy_type: 'http',
        forward_scheme: prev.forward_scheme === 'https' ? 'https' : 'http',
      }
    })
  }

  const updateStreamProtocol = (protocol: StreamProtocol) => {
    setFormData((prev) => ({
      ...prev,
      stream_protocol: protocol,
      forward_scheme: protocol,
      // UDP supports neither passthrough (ssl_preread) nor TLS termination —
      // reset the TLS mode to 'none' (clear preread, ssl_enabled and cert).
      stream_ssl_preread: protocol === 'udp' ? false : prev.stream_ssl_preread,
      ssl_enabled: protocol === 'udp' ? false : prev.ssl_enabled,
      certificate_id: protocol === 'udp' ? undefined : prev.certificate_id,
      stream_accept_proxy_protocol: protocol === 'udp' ? false : prev.stream_accept_proxy_protocol,
      stream_send_proxy_protocol: protocol === 'udp' ? false : prev.stream_send_proxy_protocol,
    }))
  }

  // Stream TLS mode is derived from the existing fields (no new model field):
  // ssl_enabled => 'terminate', stream_ssl_preread => 'passthrough', else 'none'.
  const streamTlsMode: 'none' | 'passthrough' | 'terminate' =
    formData.ssl_enabled ? 'terminate' : (formData.stream_ssl_preread ? 'passthrough' : 'none')
  const setStreamTlsMode = (mode: 'none' | 'passthrough' | 'terminate') => {
    setFormData((prev) => ({
      ...prev,
      stream_ssl_preread: mode === 'passthrough',
      ssl_enabled: mode === 'terminate',
      certificate_id: mode === 'terminate' ? prev.certificate_id : undefined,
    }))
  }

  const updateNumberField = (
    field: 'stream_listen_port' | 'stream_proxy_connect_timeout' | 'stream_proxy_timeout',
    value: string,
  ) => {
    if (value === '' || /^\d+$/.test(value)) {
      setFormData((prev) => ({ ...prev, [field]: value === '' ? 0 : parseInt(value, 10) }))
    }
  }

  const clearPortError = (field: 'forward_port' | 'stream_listen_port') => {
    setErrors(prev => {
      const { [field]: _removed, ...rest } = prev
      return rest
    })
  }

  const validateListenPort = () => {
    const port = Number(formData.stream_listen_port || 0)
    if (port < 1 || port > 65535) {
      setErrors(prev => ({ ...prev, stream_listen_port: t('validation.portRange') }))
    } else {
      clearPortError('stream_listen_port')
    }
  }

  const ddnsProviders = dnsProviders.filter((p) =>
    DDNS_SUPPORTED_PROVIDER_TYPES.includes(p.provider_type)
  )
  const ddnsEnabled = !!formData.ddns_enabled

  const listenHostDisplay = formData.stream_listen_host?.trim() || '*'
  const listenPortDisplay = formData.stream_listen_port || '??'
  const sourceLabel = isStream ? t('form.basic.streamNames') : t('form.basic.domainNames')
  const sourcePlaceholder = isStream ? t('form.basic.streamNamePlaceholder') : t('form.basic.domainPlaceholder')

  return (
    <div className="space-y-6">
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
          {t('form.basic.proxyMode')}
        </label>
        <div className="grid grid-cols-2 gap-2">
          {[
            { id: 'http', label: t('form.basic.httpMode'), desc: t('form.basic.httpModeDescription') },
            { id: 'stream', label: t('form.basic.streamMode'), desc: t('form.basic.streamModeDescription') },
          ].map((mode) => (
            <button
              key={mode.id}
              type="button"
              onClick={() => switchProxyType(mode.id as 'http' | 'stream')}
              className={`rounded-lg border px-4 py-3 text-left transition-colors ${
                formData.proxy_type === mode.id
                  ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
                  : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:border-slate-600'
              }`}
            >
              <span className="block text-sm font-semibold">{mode.label}</span>
              <span className="mt-1 block text-xs opacity-75">{mode.desc}</span>
            </button>
          ))}
        </div>
      </div>

      {isStream && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-900/40 dark:bg-amber-900/10">
          <div className="flex items-start gap-3">
            <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-amber-600 dark:text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div className="text-xs text-amber-800 dark:text-amber-200">
              <p className="font-semibold mb-1">{t('form.basic.streamSecurityNoticeTitle', { defaultValue: 'Stream 모드 보안 안내' })}</p>
              <p className="leading-relaxed">{t('form.basic.streamSecurityNoticeBody', { defaultValue: 'TCP/UDP stream 호스트는 HTTP 프로토콜이 없어 ModSecurity(WAF), exploit 차단, bot filter, URI 차단, rate limit, access list는 적용되지 않습니다. IP 기반 보안(banned IPs, fail2ban, GeoIP)만 stream에 효과가 있습니다.' })}</p>
            </div>
          </div>
        </div>
      )}

      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
          {sourceLabel}
          <HelpTip contentKey="help.domainNames" />
        </label>
        <div className="space-y-2">
          {formData.domain_names.map((domain, index) => (
            <div key={index} className="flex gap-2">
              <input
                type="text"
                value={domain}
                onChange={(e) => updateDomain(index, e.target.value)}
                placeholder={sourcePlaceholder}
                className="flex-1 rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
              />
              {formData.domain_names.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeDomain(index)}
                  className="p-2 text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              )}
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addDomain}
          className="mt-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 flex items-center gap-1"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          {isStream ? t('form.basic.addStreamName') : t('form.basic.addDomain')}
        </button>
        {errors.domain_names && (
          <p className="mt-2 text-sm text-red-600 dark:text-red-400">{errors.domain_names}</p>
        )}
      </div>

      {isStream && (
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
            {t('form.basic.streamListener')}
          </label>
          <div className="mb-4 p-3 bg-white dark:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-600">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <code className="px-2 py-1 bg-violet-50 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300 rounded font-medium">
                {streamProtocol}://{listenHostDisplay}:{listenPortDisplay}
              </code>
              <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
              <code className="px-2 py-1 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded font-medium">
                {streamProtocol}://{formData.forward_host || 'host'}:{portInput || '??'}
              </code>
            </div>
          </div>

          <div className="grid grid-cols-12 gap-3">
            <div className="col-span-12 sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                {t('form.basic.streamProtocol')}
              </label>
              <select
                value={streamProtocol}
                onChange={(e) => updateStreamProtocol(e.target.value as StreamProtocol)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white font-medium"
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </div>
            <div className="col-span-12 sm:col-span-6">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                {t('form.basic.streamListenHost')}
              </label>
              <input
                type="text"
                value={formData.stream_listen_host || ''}
                onChange={(e) => setFormData((prev) => ({ ...prev, stream_listen_host: e.target.value }))}
                placeholder="0.0.0.0"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
              />
            </div>
            <div className="col-span-12 sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                {t('form.basic.streamListenPort')}
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={formData.stream_listen_port || ''}
                onChange={(e) => updateNumberField('stream_listen_port', e.target.value)}
                onBlur={validateListenPort}
                placeholder="5432"
                className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400 text-center font-mono ${errors.stream_listen_port ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
              />
              {errors.stream_listen_port && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">{errors.stream_listen_port}</p>
              )}
            </div>
          </div>

          <div className="mt-4">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
              {t('form.stream.tlsMode.label')}
            </label>
            <select
              value={streamTlsMode}
              disabled={streamProtocol === 'udp'}
              onChange={(e) => setStreamTlsMode(e.target.value as 'none' | 'passthrough' | 'terminate')}
              className={`w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white font-medium ${streamProtocol === 'udp' ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <option value="none">{t('form.stream.tlsMode.none')}</option>
              <option value="passthrough">{t('form.stream.tlsMode.passthrough')}</option>
              <option value="terminate">{t('form.stream.tlsMode.terminate')}</option>
            </select>
            <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">{t('form.stream.tlsMode.help')}</p>

            {streamTlsMode === 'terminate' && (
              <div className="mt-3">
                <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                  {t('form.stream.tlsMode.certLabel')}
                </label>
                <select
                  value={formData.certificate_id || ''}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      certificate_id: e.target.value || undefined,
                    }))
                  }
                  className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white ${errors.certificate_id ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
                >
                  <option value="">{t('form.ssl.selectCertificate')}...</option>
                  {availableCerts.map((cert) => (
                    <option key={cert.id} value={cert.id}>
                      {cert.domain_names.join(', ')} ({cert.provider})
                    </option>
                  ))}
                </select>
                {errors.certificate_id && (
                  <p className="mt-1 text-sm text-red-600 dark:text-red-400">{errors.certificate_id}</p>
                )}
                {availableCerts.length === 0 && (
                  <p className="mt-2 text-xs text-amber-600 bg-amber-50 p-2 rounded flex items-center gap-2 dark:text-amber-400 dark:bg-amber-900/20">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    {t('form.ssl.noCertificate')}
                  </p>
                )}
              </div>
            )}
          </div>

          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${streamProtocol === 'udp' ? 'opacity-50' : 'cursor-pointer border-slate-200 dark:border-slate-700'}`}>
              <input
                type="checkbox"
                checked={!!formData.stream_accept_proxy_protocol}
                disabled={streamProtocol === 'udp'}
                onChange={(e) => setFormData((prev) => ({ ...prev, stream_accept_proxy_protocol: e.target.checked }))}
                className="mt-0.5 rounded border-slate-300 text-primary-600 focus:ring-primary-500"
              />
              <span>
                <span className="block font-medium text-slate-700 dark:text-slate-300">{t('form.basic.streamAcceptProxyProtocol')}</span>
                <span className="text-xs text-slate-500 dark:text-slate-400">{t('form.basic.streamAcceptProxyProtocolDescription')}</span>
              </span>
            </label>
            <label className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${streamProtocol === 'udp' ? 'opacity-50' : 'cursor-pointer border-slate-200 dark:border-slate-700'}`}>
              <input
                type="checkbox"
                checked={!!formData.stream_send_proxy_protocol}
                disabled={streamProtocol === 'udp'}
                onChange={(e) => setFormData((prev) => ({ ...prev, stream_send_proxy_protocol: e.target.checked }))}
                className="mt-0.5 rounded border-slate-300 text-primary-600 focus:ring-primary-500"
              />
              <span>
                <span className="block font-medium text-slate-700 dark:text-slate-300">{t('form.basic.streamSendProxyProtocol')}</span>
                <span className="text-xs text-slate-500 dark:text-slate-400">{t('form.basic.streamSendProxyProtocolDescription')}</span>
              </span>
            </label>
          </div>

          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                {t('form.basic.streamConnectTimeout')}
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={formData.stream_proxy_connect_timeout || ''}
                onChange={(e) => updateNumberField('stream_proxy_connect_timeout', e.target.value)}
                placeholder="default"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                {t('form.basic.streamProxyTimeout')}
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={formData.stream_proxy_timeout || ''}
                onChange={(e) => updateNumberField('stream_proxy_timeout', e.target.value)}
                placeholder="default"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
              />
            </div>
          </div>
        </div>
      )}

      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
          {isStream ? t('form.basic.streamUpstream') : t('form.basic.forwardHost')}
          <HelpTip contentKey="help.forwardHost" />
        </label>

        {!isStream && (
          <div className="mb-4 p-3 bg-white dark:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-600">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-slate-500 dark:text-slate-400">→</span>
              <code className="px-2 py-1 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded font-medium">
                {formData.domain_names[0] || 'your-domain.com'}
              </code>
              <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
              <code className="px-2 py-1 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded font-medium">
                {formData.forward_scheme}://{formData.forward_host || 'host'}:{portInput || '??'}
              </code>
            </div>
          </div>
        )}

        <div className="grid grid-cols-12 gap-3">
          {!isStream && (
            <div className="col-span-12 sm:col-span-3">
              <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-1">
                {t('form.basic.forwardScheme')}
                <HelpTip contentKey="help.forwardScheme" />
              </label>
              <select
                value={formData.forward_scheme}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    forward_scheme: e.target.value as 'http' | 'https',
                  }))
                }
                className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white font-medium"
              >
                <option value="http">http://</option>
                <option value="https">https://</option>
              </select>
            </div>
          )}

          <div className={isStream ? 'col-span-12 sm:col-span-8' : 'col-span-12 sm:col-span-6'}>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-1">
              {isStream ? t('form.basic.backendHost') : t('form.basic.forwardHost')}
              <HelpTip contentKey="help.forwardHost" />
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={formData.forward_host}
                onChange={(e) =>
                  // Manual edit of the target clears any Docker container binding so
                  // it is treated as a plain IP/FQDN target (non-regression). Both
                  // the container name and network are cleared together so the
                  // reconcile scheduler doesn't try to resolve a partial binding.
                  setFormData((prev) => ({
                    ...prev,
                    forward_host: e.target.value,
                    forward_container_name: undefined,
                    forward_container_network: undefined,
                  }))
                }
                placeholder={t('form.basic.forwardHostPlaceholder')}
                className={`flex-1 rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400 ${errors.forward_host ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
              />
              <button
                type="button"
                onClick={() => setDockerSelectorOpen(true)}
                className="flex-shrink-0 px-3 py-2.5 text-xs font-medium bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 border border-blue-200 dark:border-blue-800 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors flex items-center gap-1.5"
                title={t('form.basic.dockerBrowse')}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                </svg>
                {t('form.basic.dockerBrowseShort')}
              </button>
            </div>
            {errors.forward_host && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{errors.forward_host}</p>
            )}
            {formData.forward_container_name && (
              <p className="mt-1.5 inline-flex items-center gap-1.5 text-xs text-blue-700 dark:text-blue-300">
                <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                </svg>
                {formData.forward_container_network
                  ? t('form.basic.dockerContainerTargetWithNetwork', { name: formData.forward_container_name, network: formData.forward_container_network })
                  : t('form.basic.dockerContainerTarget', { name: formData.forward_container_name })}
              </p>
            )}
          </div>

          <div className={isStream ? 'col-span-12 sm:col-span-4' : 'col-span-12 sm:col-span-3'}>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-1">
              {isStream ? t('form.basic.backendPort') : t('form.basic.forwardPort')}
              <HelpTip contentKey="help.forwardPort" />
            </label>
            <input
              type="text"
              inputMode="numeric"
              value={portInput}
              onChange={(e) => {
                const value = e.target.value
                if (value === '' || /^\d+$/.test(value)) {
                  setPortInput(value)
                }
              }}
              onBlur={() => {
                const port = parseInt(portInput)
                if (portInput && (isNaN(port) || port < 1 || port > 65535)) {
                  setErrors(prev => ({ ...prev, forward_port: t('validation.portRange') }))
                } else {
                  clearPortError('forward_port')
                }
              }}
              placeholder="80"
              className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400 text-center font-mono ${errors.forward_port ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
            />
            {errors.forward_port && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{errors.forward_port}</p>
            )}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <span className="text-xs text-slate-500 dark:text-slate-400">{t('common:labels.port')}:</span>
          {(isStream ? [22, 25, 3306, 5432, 6379, 27017] : [80, 443, 3000, 8080, 8443]).map(port => (
            <button
              key={port}
              type="button"
              onClick={() => setPortInput(port.toString())}
              className={`px-2 py-0.5 text-xs rounded ${portInput === port.toString()
                ? 'bg-primary-100 text-primary-700 dark:bg-primary-900/40 dark:text-primary-300'
                : 'bg-slate-200 text-slate-600 hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600'
              }`}
            >
              {port}
            </button>
          ))}
        </div>
      </div>

      {/* DDNS Auto-Registration */}
      <div className={`p-4 rounded-lg border-2 transition-colors ${ddnsEnabled ? 'bg-cyan-50 border-cyan-200 dark:bg-cyan-900/20 dark:border-cyan-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center ${ddnsEnabled ? 'bg-cyan-100 dark:bg-cyan-900/40' : 'bg-slate-200 dark:bg-slate-700'}`}>
              <svg className={`w-5 h-5 ${ddnsEnabled ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                {t('form.basic.ddnsAutoRegister')}
                <HelpTip content={t('form.basic.ddnsAutoRegisterDescription')} />
              </span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.basic.ddnsAutoRegisterDescription')}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              const enabled = !ddnsEnabled
              setFormData(prev => ({
                ...prev,
                ddns_enabled: enabled,
                // Clear the provider when turning DDNS off.
                ddns_provider_id: enabled ? prev.ddns_provider_id : undefined,
              }))
              setErrors(prev => {
                const { ddns_provider_id: _removed, ...rest } = prev
                return rest
              })
            }}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${ddnsEnabled ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-600'}`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${ddnsEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>

        {ddnsEnabled && (
          <div className="mt-4">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
              {t('form.basic.ddnsProvider')}
            </label>
            <select
              value={formData.ddns_provider_id || ''}
              onChange={(e) => {
                const value = e.target.value || undefined
                setFormData(prev => ({ ...prev, ddns_provider_id: value }))
                if (value) {
                  setErrors(prev => {
                    const { ddns_provider_id: _removed, ...rest } = prev
                    return rest
                  })
                }
              }}
              disabled={ddnsProviders.length === 0}
              className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white ${errors.ddns_provider_id ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'} ${ddnsProviders.length === 0 ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <option value="">{t('form.basic.ddnsSelectProvider')}</option>
              {ddnsProviders.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.provider_type})
                </option>
              ))}
            </select>
            {errors.ddns_provider_id && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{errors.ddns_provider_id}</p>
            )}
            {ddnsProviders.length === 0 ? (
              <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">{t('form.basic.ddnsNoProviders')}</p>
            ) : (
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{t('form.basic.ddnsProviderHint')}</p>
            )}
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t('form.basic.ddnsStatusHint')}
            </p>
          </div>
        )}
      </div>

      <DockerContainerSelector
        isOpen={dockerSelectorOpen}
        onClose={() => setDockerSelectorOpen(false)}
        onSelect={handleDockerSelect}
      />
    </div>
  )
}

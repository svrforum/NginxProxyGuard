import type { CreateProxyHostRequest } from '../../../types/proxy-host'
import type { CreateCertificateRequest } from '../../../types/certificate'
import type { CertificateState } from '../types'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../common/HelpTip'

interface DNSProvider {
  id: string
  name: string
  provider_type: string
}

interface SSLTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  certState: CertificateState
  setCertMode: (mode: 'select' | 'create') => void
  setNewCertData: React.Dispatch<React.SetStateAction<CreateCertificateRequest>>
  errors: Record<string, string | undefined>
  availableCerts: Array<{
    id: string
    domain_names: string[]
    provider: string
    status: string
  }>
  pendingCerts: Array<{
    id: string
    domain_names: string[]
    provider: string
    status: string
  }>
  dnsProviders: DNSProvider[]
}

export function SSLTabContent({
  formData,
  setFormData,
  certState,
  setCertMode,
  setNewCertData,
  errors,
  availableCerts,
  pendingCerts,
  dnsProviders,
}: SSLTabProps) {
  const { t } = useTranslation('proxyHost')
  const { mode: certMode, data: newCertData, creating: certCreating, error: certError, success: certSuccess, progress: certProgress, elapsedTime: certElapsedTime } = certState

  return (
    <div className="space-y-6">
      {/* SSL Enable Toggle */}
      <div className={`p-4 rounded-lg border-2 transition-colors ${formData.ssl_enabled ? 'bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
        }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.ssl_enabled ? 'bg-green-100 dark:bg-green-900/40' : 'bg-slate-200 dark:bg-slate-700'
              }`}>
              <svg className={`w-5 h-5 ${formData.ssl_enabled ? 'text-green-600 dark:text-green-400' : 'text-slate-400 dark:text-slate-500'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                {t('form.ssl.enabled')}
                <HelpTip contentKey="help.ssl.enabled" />
              </span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.ssl.enabledDescription')}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              const enabled = !formData.ssl_enabled
              setFormData(prev => ({
                ...prev,
                ssl_enabled: enabled,
                ssl_http2: enabled ? true : prev.ssl_http2,
              }))
            }}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${formData.ssl_enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
              }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${formData.ssl_enabled ? 'translate-x-6' : 'translate-x-1'
                }`}
            />
          </button>
        </div>
      </div>

      {formData.ssl_enabled && (
        <>
          {/* Certificate Selection/Creation */}
          <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
                {t('form.ssl.certificate')}
                <HelpTip contentKey="help.ssl.certificate" />
              </label>
              <div className="flex gap-1 bg-slate-200 dark:bg-slate-700 rounded-lg p-0.5">
                <button
                  type="button"
                  onClick={() => setCertMode('select')}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${certMode === 'select' ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                >
                  {t('form.ssl.existingCertificate')}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setCertMode('create')
                    setNewCertData(prev => ({
                      ...prev,
                      domain_names: formData.domain_names.filter(d => d.trim())
                    }))
                  }}
                  className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${certMode === 'create' ? 'bg-white dark:bg-slate-600 text-slate-900 dark:text-white shadow-sm' : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                >
                  + {t('form.ssl.createCertificate')}
                </button>
              </div>
            </div>

            {certMode === 'select' ? (
              <>
                <select
                  value={formData.certificate_id || ''}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      certificate_id: e.target.value || undefined,
                    }))
                  }
                  className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white ${errors.certificate_id ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'
                    }`}
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
                {availableCerts.length === 0 && !pendingCerts.length && (
                  <p className="mt-2 text-xs text-amber-600 bg-amber-50 p-2 rounded flex items-center gap-2">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    {t('form.ssl.noCertificate')}
                  </p>
                )}
                {pendingCerts.length > 0 && (
                  <p className="mt-2 text-xs text-blue-600 bg-blue-50 p-2 rounded flex items-center gap-2">
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    {t('form.ssl.pendingCertificates')} ({pendingCerts.length})
                  </p>
                )}
              </>
            ) : (
              <div className="space-y-4">
                {/* Certificate Type Selection */}
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-2">{t('form.ssl.certificateProvider')}</label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setNewCertData(prev => ({ ...prev, provider: 'letsencrypt' }))}
                      className={`p-3 rounded-lg border-2 text-left transition-colors ${newCertData.provider === 'letsencrypt'
                        ? 'bg-green-50 border-green-300 dark:bg-green-900/20 dark:border-green-800'
                        : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500'
                        }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-lg">🔐</span>
                        <div>
                          <span className="text-sm font-medium text-slate-900 dark:text-white">Let's Encrypt</span>
                          <p className="text-xs text-slate-500 dark:text-slate-400">Free, auto-renew</p>
                        </div>
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => setNewCertData(prev => ({ ...prev, provider: 'selfsigned' }))}
                      className={`p-3 rounded-lg border-2 text-left transition-colors ${newCertData.provider === 'selfsigned'
                        ? 'bg-amber-50 border-amber-300 dark:bg-amber-900/20 dark:border-amber-800'
                        : 'bg-white dark:bg-slate-700 border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500'
                        }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-lg">📜</span>
                        <div>
                          <span className="text-sm font-medium text-slate-900 dark:text-white">Self-Signed</span>
                          <p className="text-xs text-slate-500 dark:text-slate-400">For testing</p>
                        </div>
                      </div>
                    </button>
                  </div>
                </div>

                {/* Domains to cover */}
                <div>
                  <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">Domains (from above)</label>
                  <div className="flex flex-wrap gap-1.5">
                    {newCertData.domain_names.length > 0 ? (
                      newCertData.domain_names.map((domain, i) => (
                        <span key={i} className="px-2 py-1 bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 text-xs rounded-full">
                          {domain}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500 dark:text-slate-400 italic">Add domains in the Basic tab first</span>
                    )}
                  </div>
                </div>

                {/* Let's Encrypt specific options */}
                {newCertData.provider === 'letsencrypt' && (
                  <>
                    {/* DNS Provider */}
                    {dnsProviders.length > 0 && (
                      <div>
                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                          {t('form.ssl.dnsProvider')} ({t('form.ssl.dnsChallenge')})
                        </label>
                        <select
                          value={newCertData.dns_provider_id || ''}
                          onChange={(e) =>
                            setNewCertData((prev) => ({
                              ...prev,
                              dns_provider_id: e.target.value || undefined,
                            }))
                          }
                          className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
                        >
                          <option value="">{t('form.ssl.httpChallenge')}</option>
                          {dnsProviders.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name} ({p.provider_type})
                            </option>
                          ))}
                        </select>
                        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                          Use DNS challenge for wildcard certs or when port 80 isn't accessible
                        </p>
                      </div>
                    )}

                    {/* Auto-renew */}
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newCertData.auto_renew}
                        onChange={(e) =>
                          setNewCertData((prev) => ({
                            ...prev,
                            auto_renew: e.target.checked,
                          }))
                        }
                        className="rounded border-slate-300 text-green-600 focus:ring-green-500"
                      />
                      <span className="text-sm text-slate-700 dark:text-slate-300">Auto-renew before expiry</span>
                    </label>
                  </>
                )}

                {/* Self-signed validity */}
                {newCertData.provider === 'selfsigned' && (
                  <div>
                    <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5">
                      Validity (days)
                    </label>
                    <input
                      type="number"
                      value={newCertData.validity_days || 365}
                      onChange={(e) =>
                        setNewCertData((prev) => ({
                          ...prev,
                          validity_days: parseInt(e.target.value) || 365,
                        }))
                      }
                      min={1}
                      max={3650}
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
                    />
                  </div>
                )}

                {/* Certificate issuance progress */}
                {certCreating && certProgress && (
                  <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                    <div className="flex items-center gap-3 mb-3">
                      <svg className="w-5 h-5 text-blue-600 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      <div className="flex-1">
                        <p className="text-sm font-medium text-blue-800">{certProgress}</p>
                        <p className="text-xs text-blue-600 mt-0.5">
                          {newCertData.provider === 'letsencrypt'
                            ? 'Let\'s Encrypt is validating your domain. This usually takes 10-30 seconds.'
                            : 'Generating self-signed certificate...'}
                        </p>
                      </div>
                    </div>
                    {/* Progress bar */}
                    <div className="relative h-2 bg-blue-200 rounded-full overflow-hidden">
                      <div
                        className="absolute inset-y-0 left-0 bg-blue-500 rounded-full transition-all duration-500"
                        style={{ width: `${Math.min((certElapsedTime / 30) * 100, 95)}%` }}
                      />
                      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer" />
                    </div>
                    <p className="text-xs text-blue-500 mt-2 text-center">
                      Elapsed: {certElapsedTime}s (timeout: 120s)
                    </p>
                  </div>
                )}

                {certError && (
                  <div className="p-2 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700 flex items-center gap-2">
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {certError}
                  </div>
                )}
                {certSuccess && (
                  <div className="p-2 bg-green-50 border border-green-200 rounded-lg text-sm text-green-700 flex items-center gap-2">
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {certSuccess}
                  </div>
                )}

                {/* Info message - only show when not creating */}
                {!certCreating && (
                  <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-700 flex items-start gap-2">
                    <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>
                      {newCertData.provider === 'letsencrypt'
                        ? 'Let\'s Encrypt certificate will be issued when you click "Create Proxy Host". This may take 10-30 seconds.'
                        : 'Certificate will be created when you click "Create Proxy Host".'}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* SSL Options */}
          <div className="grid grid-cols-2 gap-4">
            {/* Force HTTPS */}
            <label className={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${formData.ssl_force_https ? 'bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}>
              <input
                type="checkbox"
                checked={formData.ssl_force_https}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    ssl_force_https: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <div>
                <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                  {t('form.ssl.forceHttps')}
                  <HelpTip contentKey="help.ssl.forceHttps" />
                </span>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.ssl.forceHttpsDescription')}</p>
              </div>
            </label>

            {/* HTTP/2 */}
            <label className={`flex items-center gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${formData.ssl_http2 ? 'bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800'
              }`}>
              <input
                type="checkbox"
                checked={formData.ssl_http2}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    ssl_http2: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <div>
                <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                  {t('form.ssl.http2')}
                  <HelpTip contentKey="help.ssl.http2" />
                </span>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.ssl.http2Description')}</p>
              </div>
            </label>
          </div>

          {/* HTTP/3 */}
          <div className={`p-4 rounded-lg border-2 transition-colors ${formData.ssl_http3 ? 'bg-emerald-50 border-emerald-200 dark:bg-emerald-900/20 dark:border-emerald-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
            }`}>
            <label className="flex items-center justify-between cursor-pointer">
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${formData.ssl_http3 ? 'bg-emerald-100 dark:bg-emerald-900/40' : 'bg-slate-200 dark:bg-slate-700'
                  }`}>
                  <span className="text-lg">🚀</span>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                      {t('form.ssl.http3')}
                      <HelpTip contentKey="help.ssl.http3" />
                    </span>
                    <span className="px-1.5 py-0.5 text-xs font-medium bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 rounded">Fast</span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400">{t('form.ssl.http3Description')}</p>
                </div>
              </div>
              <input
                type="checkbox"
                checked={formData.ssl_http3}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    ssl_http3: e.target.checked,
                  }))
                }
                className="rounded border-slate-300 text-emerald-600 focus:ring-emerald-500 h-5 w-5"
              />
            </label>
            {formData.ssl_http3 && (
              <p className="mt-3 text-xs text-slate-600 dark:text-slate-300 bg-white dark:bg-slate-800 p-2 rounded border border-slate-200 dark:border-slate-700">
                HTTP/3 uses QUIC protocol over UDP port 443. The Alt-Svc header will be sent to advertise HTTP/3 support to browsers.
              </p>
            )}
          </div>

        </>
      )}

      {!formData.ssl_enabled && (
        <div className="text-center py-8 text-slate-500">
          <svg className="w-12 h-12 mx-auto mb-3 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <p>{t('form.ssl.disabledHint')}</p>
        </div>
      )}
    </div>
  )
}

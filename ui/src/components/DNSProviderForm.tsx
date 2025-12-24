import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { createDNSProvider, updateDNSProvider, testDNSProvider } from '../api/dns-providers'
import { useTranslation } from 'react-i18next'
import { HelpTip } from './common/HelpTip'
import type { DNSProvider, CreateDNSProviderRequest } from '../types/certificate'

interface DNSProviderFormProps {
  provider?: DNSProvider | null
  onClose: () => void
  onSuccess: () => void
}

type ProviderType = 'cloudflare' | 'route53' | 'duckdns' | 'dynu' | 'manual'

export default function DNSProviderForm({ provider, onClose, onSuccess }: DNSProviderFormProps) {
  const { t } = useTranslation('certificates')
  const isEditing = !!provider

  const [name, setName] = useState(provider?.name || '')
  const [providerType, setProviderType] = useState<ProviderType>(
    (provider?.provider_type as ProviderType) || 'cloudflare'
  )
  const [isDefault, setIsDefault] = useState(provider?.is_default || false)
  const [error, setError] = useState('')
  const [testResult, setTestResult] = useState<'success' | 'failed' | null>(null)
  const [isTesting, setIsTesting] = useState(false)

  // Cloudflare credentials
  const [cfApiToken, setCfApiToken] = useState('')
  const [cfApiKey, setCfApiKey] = useState('')
  const [cfEmail, setCfEmail] = useState('')
  const [cfZoneId, setCfZoneId] = useState('')

  // Route53 credentials
  const [awsAccessKeyId, setAwsAccessKeyId] = useState('')
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState('')
  const [awsRegion, setAwsRegion] = useState('us-east-1')
  const [awsHostedZoneId, setAwsHostedZoneId] = useState('')

  // DuckDNS credentials
  const [duckdnsToken, setDuckdnsToken] = useState('')

  // Dynu credentials
  const [dynuApiKey, setDynuApiKey] = useState('')

  const buildCredentials = (): Record<string, string> => {
    if (providerType === 'cloudflare') {
      const creds: Record<string, string> = {}
      if (cfApiToken) creds.api_token = cfApiToken
      if (cfApiKey) creds.api_key = cfApiKey
      if (cfEmail) creds.email = cfEmail
      if (cfZoneId) creds.zone_id = cfZoneId
      return creds
    }
    if (providerType === 'route53') {
      const creds: Record<string, string> = {}
      if (awsAccessKeyId) creds.access_key_id = awsAccessKeyId
      if (awsSecretAccessKey) creds.secret_access_key = awsSecretAccessKey
      if (awsRegion) creds.region = awsRegion
      if (awsHostedZoneId) creds.hosted_zone_id = awsHostedZoneId
      return creds
    }
    if (providerType === 'duckdns') {
      const creds: Record<string, string> = {}
      if (duckdnsToken) creds.token = duckdnsToken
      return creds
    }
    if (providerType === 'dynu') {
      const creds: Record<string, string> = {}
      if (dynuApiKey) creds.api_key = dynuApiKey
      return creds
    }
    return {}
  }

  const createMutation = useMutation({
    mutationFn: createDNSProvider,
    onSuccess: () => {
      onSuccess()
    },
    onError: (err: Error) => {
      setError(err.message || t('dnsProviders.form.errors.createFailed'))
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CreateDNSProviderRequest> }) =>
      updateDNSProvider(id, data),
    onSuccess: () => {
      onSuccess()
    },
    onError: (err: Error) => {
      setError(err.message || t('dnsProviders.form.errors.updateFailed'))
    },
  })

  const handleTest = async () => {
    setTestResult(null)
    setError('')
    setIsTesting(true)

    const data: CreateDNSProviderRequest = {
      name,
      provider_type: providerType,
      credentials: buildCredentials(),
      is_default: isDefault,
    }

    try {
      const success = await testDNSProvider(data)
      setTestResult(success ? 'success' : 'failed')
    } catch {
      setTestResult('failed')
    } finally {
      setIsTesting(false)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!name.trim()) {
      setError(t('dnsProviders.form.errors.nameRequired'))
      return
    }

    const data: CreateDNSProviderRequest = {
      name: name.trim(),
      provider_type: providerType,
      credentials: buildCredentials(),
      is_default: isDefault,
    }

    if (isEditing && provider) {
      updateMutation.mutate({ id: provider.id, data })
    } else {
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
              {isEditing ? t('dnsProviders.form.editTitle') : t('dnsProviders.form.addTitle')}
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

          {testResult === 'success' && (
            <div className="bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 rounded-lg p-4 text-green-700 dark:text-green-400 text-sm flex items-center gap-2">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              {t('dnsProviders.form.test.success')}
            </div>
          )}

          {testResult === 'failed' && (
            <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400 text-sm flex items-center gap-2">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              {t('dnsProviders.form.test.failed')}
            </div>
          )}

          {/* Provider Name */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('dnsProviders.form.providerName')}
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('dnsProviders.form.providerNamePlaceholder')}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
              required
            />
          </div>

          {/* Provider Type */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('dnsProviders.form.providerType')}
            </label>
            <select
              value={providerType}
              onChange={(e) => setProviderType(e.target.value as ProviderType)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="cloudflare">Cloudflare</option>
              <option value="route53">AWS Route 53</option>
              <option value="duckdns">DuckDNS</option>
              <option value="dynu">Dynu</option>
              <option value="manual">{t('dnsProviders.types.manual')}</option>
            </select>
          </div>

          {/* Cloudflare Credentials */}
          {providerType === 'cloudflare' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-orange-500" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M16.5 11.38l-.21.2-.14.27-.42.16-.3.09c-.2.16-.37.36-.52.58-.2.3-.32.63-.35.98h-.02l-.17.33-.2.23c-.1.08-.22.14-.34.18-.13.03-.27.04-.4.04-.08 0-.16-.02-.24-.05a.4.4 0 01-.16-.12" />
                </svg>
                {t('dnsProviders.form.cloudflare.title')}
              </h3>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('dnsProviders.form.cloudflare.apiToken')}
                  <HelpTip content={t('dnsProviders.form.cloudflare.apiTokenHelp')} />
                </label>
                <input
                  type="password"
                  value={cfApiToken}
                  onChange={(e) => setCfApiToken(e.target.value)}
                  placeholder={t('dnsProviders.form.cloudflare.apiTokenPlaceholder')}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                />
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('dnsProviders.form.cloudflare.apiTokenHelp')}
                </p>
              </div>

              <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('dnsProviders.form.cloudflare.orGlobalKey')}</p>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      {t('dnsProviders.form.cloudflare.apiKey')}
                    </label>
                    <input
                      type="password"
                      value={cfApiKey}
                      onChange={(e) => setCfApiKey(e.target.value)}
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      {t('dnsProviders.form.cloudflare.email')}
                    </label>
                    <input
                      type="email"
                      value={cfEmail}
                      onChange={(e) => setCfEmail(e.target.value)}
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                    />
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('dnsProviders.form.cloudflare.zoneId')}
                  <HelpTip content={t('dnsProviders.form.cloudflare.zoneIdPlaceholder')} />
                </label>
                <input
                  type="text"
                  value={cfZoneId}
                  onChange={(e) => setCfZoneId(e.target.value)}
                  placeholder={t('dnsProviders.form.cloudflare.zoneIdPlaceholder')}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                />
              </div>
            </div>
          )}

          {/* Route53 Credentials */}
          {providerType === 'route53' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                </svg>
                {t('dnsProviders.form.route53.title')}
              </h3>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('dnsProviders.form.route53.accessKeyId')}
                  </label>
                  <input
                    type="text"
                    value={awsAccessKeyId}
                    onChange={(e) => setAwsAccessKeyId(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('dnsProviders.form.route53.secretAccessKey')}
                  </label>
                  <input
                    type="password"
                    value={awsSecretAccessKey}
                    onChange={(e) => setAwsSecretAccessKey(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('dnsProviders.form.route53.region')}
                  </label>
                  <input
                    type="text"
                    value={awsRegion}
                    onChange={(e) => setAwsRegion(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    {t('dnsProviders.form.route53.hostedZoneId')}
                  </label>
                  <input
                    type="text"
                    value={awsHostedZoneId}
                    onChange={(e) => setAwsHostedZoneId(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                  />
                </div>
              </div>
            </div>
          )}

          {/* DuckDNS Credentials */}
          {providerType === 'duckdns' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                </svg>
                {t('dnsProviders.form.duckdns.title')}
              </h3>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('dnsProviders.form.duckdns.token')}
                  <HelpTip content={t('dnsProviders.form.duckdns.tokenHelp')} />
                </label>
                <input
                  type="password"
                  value={duckdnsToken}
                  onChange={(e) => setDuckdnsToken(e.target.value)}
                  placeholder={t('dnsProviders.form.duckdns.tokenPlaceholder')}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                />
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('dnsProviders.form.duckdns.tokenHelp')}
                </p>
              </div>
            </div>
          )}

          {/* Dynu Credentials */}
          {providerType === 'dynu' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                </svg>
                {t('dnsProviders.form.dynu.title')}
              </h3>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('dnsProviders.form.dynu.apiKey')}
                  <HelpTip content={t('dnsProviders.form.dynu.apiKeyHelp')} />
                </label>
                <input
                  type="password"
                  value={dynuApiKey}
                  onChange={(e) => setDynuApiKey(e.target.value)}
                  placeholder={t('dnsProviders.form.dynu.apiKeyPlaceholder')}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                />
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('dnsProviders.form.dynu.apiKeyHelp')}
                </p>
              </div>
            </div>
          )}

          {/* Manual DNS info */}
          {providerType === 'manual' && (
            <div className="bg-amber-50 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-800 rounded-xl p-5">
              <div className="flex items-start gap-3">
                <svg className="w-5 h-5 text-amber-600 dark:text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <h4 className="text-sm font-medium text-amber-800 dark:text-amber-300">{t('dnsProviders.form.manual.title')}</h4>
                  <p className="mt-1 text-sm text-amber-700 dark:text-amber-400">
                    {t('dnsProviders.form.manual.desc')}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Is Default Toggle */}
          <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl border border-transparent dark:border-slate-700">
            <div>
              <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('dnsProviders.form.setDefault')}</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('dnsProviders.form.setDefaultDesc')}</p>
            </div>
            <button
              type="button"
              onClick={() => setIsDefault(!isDefault)}
              className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-slate-800 ${isDefault ? 'bg-primary-600' : 'bg-slate-200 dark:bg-slate-600'
                }`}
            >
              <span
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${isDefault ? 'translate-x-5' : 'translate-x-0'
                  }`}
              />
            </button>
          </div>

          {/* Actions */}
          <div className="flex justify-between pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={handleTest}
              disabled={isPending || isTesting || providerType === 'manual'}
              className="px-4 py-2 text-sm font-medium text-primary-600 dark:text-primary-400 bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800 rounded-lg hover:bg-primary-100 dark:hover:bg-primary-900/40 focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:opacity-50 flex items-center gap-2"
            >
              {isTesting && (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}

              {t('dnsProviders.form.test.button')}
            </button>

            <div className="flex gap-3">
              <button
                type="button"
                onClick={onClose}
                disabled={isPending}
                className="px-4 py-2 text-sm font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
              >
                {t('dnsProviders.form.cancel')}
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
                {isEditing ? t('dnsProviders.form.update') : t('dnsProviders.form.create')}
              </button>
            </div>
          </div>
        </form>
      </div >
    </div >
  )
}

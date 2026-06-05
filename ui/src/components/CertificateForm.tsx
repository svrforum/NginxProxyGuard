import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createCertificate, uploadCertificate } from '../api/certificates'
import { listDNSProviders } from '../api/dns-providers'
import type { CreateCertificateRequest, UploadCertificateRequest } from '../types/certificate'
import { HelpTip } from './common/HelpTip'
import { ModalShell } from './common/ModalShell'
import { CertificateLogModal } from './CertificateLogModal'

interface CertificateFormProps {
  onClose: () => void
  onSuccess: () => void
}

type ProviderType = 'letsencrypt' | 'selfsigned' | 'custom'
type ChallengeType = 'http' | 'dns'

export default function CertificateForm({ onClose, onSuccess }: CertificateFormProps) {
  const { t } = useTranslation(['certificates', 'common'])
  const [provider, setProvider] = useState<ProviderType>('selfsigned')
  const [challengeType, setChallengeType] = useState<ChallengeType>('http')
  const [domainNames, setDomainNames] = useState('')
  const [dnsProviderId, setDnsProviderId] = useState('')
  const [autoRenew, setAutoRenew] = useState(true)
  const [validityDays, setValidityDays] = useState(365)
  const [certificatePem, setCertificatePem] = useState('')
  const [privateKeyPem, setPrivateKeyPem] = useState('')
  const [issuerPem, setIssuerPem] = useState('')
  const [error, setError] = useState('')
  const [showLogModal, setShowLogModal] = useState(false)
  const [createdCertId, setCreatedCertId] = useState<string | null>(null)

  const { data: dnsProviders } = useQuery({
    queryKey: ['dns-providers'],
    queryFn: () => listDNSProviders(),
    enabled: provider === 'letsencrypt' && challengeType === 'dns',
  })

  useEffect(() => {
    if (dnsProviders?.data) {
      const defaultProvider = dnsProviders.data.find((p) => p.is_default)
      if (defaultProvider) {
        setDnsProviderId(defaultProvider.id)
      } else if (dnsProviders.data.length > 0) {
        setDnsProviderId(dnsProviders.data[0].id)
      }
    }
  }, [dnsProviders])

  const createMutation = useMutation({
    mutationFn: createCertificate,
    onSuccess: (data) => {
      // For Let's Encrypt, show log modal to track progress
      if (provider === 'letsencrypt') {
        setCreatedCertId(data.id)
        setShowLogModal(true)
      } else {
        // Self-signed certificates are created instantly
        onSuccess()
      }
    },
    onError: (err: Error) => {
      setError(err.message || t('form.errors.create'))
    },
  })

  const uploadMutation = useMutation({
    mutationFn: uploadCertificate,
    onSuccess: () => {
      onSuccess()
    },
    onError: (err: Error) => {
      setError(err.message || t('form.errors.upload'))
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    const domains = domainNames
      .split(/[,\n]/)
      .map((d) => d.trim())
      .filter((d) => d.length > 0)

    if (domains.length === 0) {
      setError(t('form.errors.domainRequired'))
      return
    }

    if (provider === 'custom') {
      if (!certificatePem || !privateKeyPem) {
        setError(t('form.errors.certKeyRequired'))
        return
      }

      const uploadData: UploadCertificateRequest = {
        domain_names: domains,
        certificate_pem: certificatePem,
        private_key_pem: privateKeyPem,
        issuer_pem: issuerPem || undefined,
      }
      uploadMutation.mutate(uploadData)
    } else {
      const createData: CreateCertificateRequest = {
        domain_names: domains,
        provider,
        auto_renew: autoRenew,
      }

      if (provider === 'letsencrypt' && challengeType === 'dns' && dnsProviderId) {
        createData.dns_provider_id = dnsProviderId
      }

      if (provider === 'selfsigned') {
        createData.validity_days = validityDays
      }

      createMutation.mutate(createData)
    }
  }

  const isPending = createMutation.isPending || uploadMutation.isPending

  // Block backdrop/ESC close while a request is in flight, mirroring the disabled close button.
  const handleClose = () => {
    if (!isPending) onClose()
  }

  return (
    <>
    <ModalShell isOpen onClose={handleClose} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="certificate-form-title">
      <div>
        <div className="p-6 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <h2 id="certificate-form-title" className="text-xl font-semibold text-slate-900 dark:text-white">{t('form.title')}</h2>
            <button
              onClick={onClose}
              disabled={isPending}
              aria-label={t('common:buttons.close')}
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

          {/* Provider Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
              {t('form.provider')}
              <HelpTip contentKey="help.provider" ns="certificates" />
            </label>
            <div className="grid grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setProvider('selfsigned')}
                className={`relative flex flex-col items-center p-4 rounded-xl border-2 transition-all ${provider === 'selfsigned'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 bg-white dark:bg-slate-800'
                  }`}
              >
                <div className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 ${provider === 'selfsigned' ? 'bg-primary-100 dark:bg-primary-900/50' : 'bg-slate-100 dark:bg-slate-700'
                  }`}>
                  <svg className={`w-5 h-5 ${provider === 'selfsigned' ? 'text-primary-600 dark:text-primary-400' : 'text-slate-500 dark:text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <span className={`text-sm font-medium ${provider === 'selfsigned' ? 'text-primary-700 dark:text-primary-300' : 'text-slate-700 dark:text-slate-300'}`}>
                  {t('form.providers.selfSigned')}
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('form.providers.selfSignedDesc')}</span>
              </button>

              <button
                type="button"
                onClick={() => setProvider('letsencrypt')}
                className={`relative flex flex-col items-center p-4 rounded-xl border-2 transition-all ${provider === 'letsencrypt'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 bg-white dark:bg-slate-800'
                  }`}
              >
                <div className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 ${provider === 'letsencrypt' ? 'bg-primary-100 dark:bg-primary-900/50' : 'bg-slate-100 dark:bg-slate-700'
                  }`}>
                  <svg className={`w-5 h-5 ${provider === 'letsencrypt' ? 'text-primary-600 dark:text-primary-400' : 'text-slate-500 dark:text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <span className={`text-sm font-medium ${provider === 'letsencrypt' ? 'text-primary-700 dark:text-primary-300' : 'text-slate-700 dark:text-slate-300'}`}>
                  {t('form.providers.letsEncrypt')}
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('form.providers.letsEncryptDesc')}</span>
              </button>

              <button
                type="button"
                onClick={() => setProvider('custom')}
                className={`relative flex flex-col items-center p-4 rounded-xl border-2 transition-all ${provider === 'custom'
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 bg-white dark:bg-slate-800'
                  }`}
              >
                <div className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 ${provider === 'custom' ? 'bg-primary-100 dark:bg-primary-900/50' : 'bg-slate-100 dark:bg-slate-700'
                  }`}>
                  <svg className={`w-5 h-5 ${provider === 'custom' ? 'text-primary-600 dark:text-primary-400' : 'text-slate-500 dark:text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                  </svg>
                </div>
                <span className={`text-sm font-medium ${provider === 'custom' ? 'text-primary-700 dark:text-primary-300' : 'text-slate-700 dark:text-slate-300'}`}>
                  {t('form.providers.custom')}
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('form.providers.customDesc')}</span>
              </button>
            </div>
          </div>

          {/* Domain Names */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
              {t('form.domains')}
              <HelpTip contentKey="help.domains" ns="certificates" />
            </label>
            <textarea
              value={domainNames}
              onChange={(e) => setDomainNames(e.target.value)}
              placeholder={t('form.domainsPlaceholder')}
              rows={3}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-3 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
              required
            />
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {t('form.domainsHint')}
            </p>
          </div>

          {/* Let's Encrypt specific options */}
          {provider === 'letsencrypt' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                {t('form.letsEncryptSettings')}
              </h3>

              {/* Challenge Type Selection */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('form.verificationMethod')}
                  <HelpTip contentKey="help.verificationMethod" ns="certificates" />
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setChallengeType('http')}
                    className={`relative flex flex-col items-start p-3 rounded-lg border-2 transition-all ${challengeType === 'http'
                      ? 'border-green-500 bg-green-50 dark:bg-green-900/20'
                      : 'border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500 bg-white dark:bg-slate-700'
                      }`}
                  >
                    <span className={`text-sm font-medium ${challengeType === 'http' ? 'text-green-700 dark:text-green-400' : 'text-slate-700 dark:text-slate-300'}`}>
                      {t('form.methods.http')}
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {t('form.methods.httpDesc')}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setChallengeType('dns')}
                    className={`relative flex flex-col items-start p-3 rounded-lg border-2 transition-all ${challengeType === 'dns'
                      ? 'border-green-500 bg-green-50 dark:bg-green-900/20'
                      : 'border-slate-200 dark:border-slate-600 hover:border-slate-300 dark:hover:border-slate-500 bg-white dark:bg-slate-700'
                      }`}
                  >
                    <span className={`text-sm font-medium ${challengeType === 'dns' ? 'text-green-700 dark:text-green-400' : 'text-slate-700 dark:text-slate-300'}`}>
                      {t('form.methods.dns')}
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {t('form.methods.dnsDesc')}
                    </span>
                  </button>
                </div>
              </div>

              {/* DNS Provider - only for DNS challenge */}
              {challengeType === 'dns' && (
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                    {t('form.dnsProvider')}
                    <HelpTip contentKey="help.dnsProvider" ns="certificates" />
                  </label>
                  <select
                    value={dnsProviderId}
                    onChange={(e) => setDnsProviderId(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                    required
                  >
                    <option value="">{t('form.selectDnsProvider')}</option>
                    {dnsProviders?.data?.map((dp) => (
                      <option key={dp.id} value={dp.id}>
                        {dp.name} ({dp.provider_type})
                        {dp.is_default ? t('form.defaultSuffix') : ''}
                      </option>
                    ))}
                  </select>
                  {(!dnsProviders?.data || dnsProviders.data.length === 0) && (
                    <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">
                      {t('form.noDnsProvider')}
                    </p>
                  )}
                </div>
              )}

              {/* HTTP Challenge Info */}
              {challengeType === 'http' && (
                <div className="bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                  <p className="text-xs text-blue-700 dark:text-blue-300">
                    <strong>{t('form.httpChallengeInfo')}</strong>
                  </p>
                </div>
              )}

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoRenew}
                  onChange={(e) => setAutoRenew(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500 dark:bg-slate-700"
                />
                <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.autoRenew')}
                  <HelpTip contentKey="help.autoRenew" ns="certificates" />
                </span>
              </label>
            </div>
          )}

          {/* Self-signed specific options */}
          {provider === 'selfsigned' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-slate-600 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {t('form.selfSignedSettings')}
              </h3>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
                  {t('form.validityPeriod')}
                  <HelpTip contentKey="help.validityPeriod" ns="certificates" />
                </label>
                <select
                  value={validityDays}
                  onChange={(e) => setValidityDays(parseInt(e.target.value))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
                >
                  <option value={30}>{t('form.daysOption', { count: 30 })}</option>
                  <option value={90}>{t('form.daysOption', { count: 90 })}</option>
                  <option value={180}>{t('form.daysOption', { count: 180 })}</option>
                  <option value={365}>{t('form.yearOption', { count: 1 })}</option>
                  <option value={730}>{t('form.yearsOption', { count: 2 })}</option>
                  <option value={1825}>{t('form.yearsOption', { count: 5 })}</option>
                </select>
              </div>
            </div>
          )}

          {/* Custom certificate upload */}
          {provider === 'custom' && (
            <div className="space-y-4 bg-slate-50 dark:bg-slate-700/50 rounded-xl p-5 border border-slate-200 dark:border-slate-600">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                <svg className="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                {t('form.uploadTitle')}
              </h3>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  {t('form.certPem')} <span className="text-red-500">*</span>
                </label>
                <textarea
                  value={certificatePem}
                  onChange={(e) => setCertificatePem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  rows={5}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-3 text-xs font-mono focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  {t('form.privateKey')} <span className="text-red-500">*</span>
                </label>
                <textarea
                  value={privateKeyPem}
                  onChange={(e) => setPrivateKeyPem(e.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  rows={5}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-3 text-xs font-mono focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                  {t('form.issuerPem')}
                </label>
                <textarea
                  value={issuerPem}
                  onChange={(e) => setIssuerPem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  rows={4}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-4 py-3 text-xs font-mono focus:ring-2 focus:ring-primary-500 focus:border-primary-500 placeholder:text-slate-400 bg-white dark:bg-slate-700 dark:text-white"
                />

                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                  {t('form.issuerHint')}
                </p>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={onClose}
              disabled={isPending}
              className="px-4 py-2 text-sm font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
            >
              {t('form.cancel')}
            </button>
            <button
              type="submit"
              disabled={isPending || (provider === 'letsencrypt' && challengeType === 'dns' && !dnsProviderId)}
              className="bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              {isPending && (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}
              {t('form.create')}
            </button>
          </div>
        </form>
      </div>
    </ModalShell>

    {/* Certificate Issuance Log Modal */}
    <CertificateLogModal
      isOpen={showLogModal}
      certificateId={createdCertId}
      onClose={() => {
        setShowLogModal(false)
        setCreatedCertId(null)
        onSuccess()
      }}
      onComplete={(success) => {
        if (!success) {
          // Keep modal open on error so user can see what happened
        }
      }}
    />
    </>
  )
}

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { updateCertificate } from '../api/certificates'
import { ModalShell } from './common/ModalShell'
import type { UploadCertificateRequest } from '../types/certificate'

interface CertificateUpdateFormProps {
  certificateId: string
  onClose: () => void
  onSuccess: () => void
}

export default function CertificateUpdateForm({ certificateId, onClose, onSuccess }: CertificateUpdateFormProps) {
  const { t } = useTranslation(['certificates', 'common'])
  const [certificatePem, setCertificatePem] = useState('')
  const [privateKeyPem, setPrivateKeyPem] = useState('')
  const [issuerPem, setIssuerPem] = useState('')
  const [error, setError] = useState('')

  const updateMutation = useMutation({
    mutationFn: (data: UploadCertificateRequest) => updateCertificate(certificateId, data),
    onSuccess: () => {
      onSuccess()
    },
    onError: (err: Error) => {
      setError(err.message || t('form.errors.update'))
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!certificatePem || !privateKeyPem) {
      setError(t('form.errors.certKeyRequired'))
      return
    }

    const uploadData: UploadCertificateRequest = {
      domain_names: [],
      certificate_pem: certificatePem,
      private_key_pem: privateKeyPem,
      issuer_pem: issuerPem || undefined,
    }
    updateMutation.mutate(uploadData)
  }

  // Block backdrop/ESC close while a request is in flight, mirroring the disabled close button.
  const handleClose = () => {
    if (!updateMutation.isPending) onClose()
  }

  return (
    <ModalShell isOpen onClose={handleClose} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="certificate-update-title">
      <div>
        <div className="p-6 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <h2 id="certificate-update-title" className="text-xl font-semibold text-slate-900 dark:text-white">{t('form.updateTitle')}</h2>
            <button
              onClick={onClose}
              disabled={updateMutation.isPending}
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

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={onClose}
              disabled={updateMutation.isPending}
              className="px-4 py-2 text-sm font-medium text-slate-700 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white"
            >
              {t('form.cancel')}
            </button>
            <button
              type="submit"
              disabled={updateMutation.isPending}
              className="bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              {updateMutation.isPending && (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}
              {t('list.update')}
            </button>
          </div>
        </form>
      </div>
    </ModalShell>
  )
}

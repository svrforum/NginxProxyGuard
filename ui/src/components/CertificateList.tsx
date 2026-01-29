import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { listCertificates, deleteCertificate, renewCertificate, downloadCertificate } from '../api/certificates';
import type { Certificate } from '../types/certificate';
import CertificateForm from './CertificateForm';
import { CertificateDetail } from './CertificateDetail';
import { CertificateLogModal } from './CertificateLogModal';

function StatusBadge({ status }: { status: Certificate['status'] }) {
  const { t } = useTranslation('certificates');


  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${status === 'pending'
      ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300'
      : status === 'issued'
        ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
        : status === 'expired' || status === 'error'
          ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
          : 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
      }`}>
      {t(`certStatuses.${status}`)}
    </span>
  );
}

function ProviderBadge({ provider }: { provider: Certificate['provider'] }) {
  const { t } = useTranslation('certificates');

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${provider === 'letsencrypt'
      ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300'
      : provider === 'selfsigned'
        ? 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'
        : 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
      }`}>
      {t(`certProviders.${provider}`)}
    </span>
  );
}

export default function CertificateList() {
  const { t, i18n } = useTranslation('certificates');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState<string | null>(null);
  const [renewingCertId, setRenewingCertId] = useState<string | null>(null);
  const [showRenewLogModal, setShowRenewLogModal] = useState(false);
  const [downloadingCertId, setDownloadingCertId] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['certificates'],
    queryFn: () => listCertificates(),
    refetchInterval: 5000, // Refresh every 5 seconds to check pending status
  });

  const deleteMutation = useMutation({
    mutationFn: deleteCertificate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });

  const renewMutation = useMutation({
    mutationFn: renewCertificate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('messages.deleteConfirm'))) {
      deleteMutation.mutate(id);
    }
  };

  const handleRenew = async (cert: Certificate) => {
    // For Let's Encrypt certificates, show log modal
    if (cert.provider === 'letsencrypt') {
      try {
        // Call API first to clear logs and start renewal
        await renewMutation.mutateAsync(cert.id);
      } catch {
        // Ignore error, will be shown in modal
      }
      // Then show modal to display progress
      setRenewingCertId(cert.id);
      setShowRenewLogModal(true);
    } else {
      renewMutation.mutate(cert.id);
    }
  };

  const handleRenewLogModalClose = () => {
    setShowRenewLogModal(false);
    setRenewingCertId(null);
    queryClient.invalidateQueries({ queryKey: ['certificates'] });
  };

  const handleDownload = async (certId: string) => {
    setDownloadingCertId(certId);
    try {
      await downloadCertificate(certId, 'all');
    } catch (err) {
      alert(err instanceof Error ? err.message : t('messages.downloadError'));
    } finally {
      setDownloadingCertId(null);
    }
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString(i18n.language);
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
        {t('messages.loadError')}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('title')}</h2>
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          + {t('list.actionNew')}
        </button>
      </div>

      {showForm && (
        <CertificateForm
          onClose={() => setShowForm(false)}
          onSuccess={() => {
            setShowForm(false);
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
        />
      )}

      <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.domains')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.status')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.provider')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.expires')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.daysLeft')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {t('list.empty')}
                </td>
              </tr>
            ) : (
              data?.data?.map((cert) => (
                <tr key={cert.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">
                      {cert.domain_names[0]}
                    </div>
                    {cert.domain_names.length > 1 && (
                      <div className="text-xs text-slate-500 dark:text-slate-400">
                        {t('list.more', { count: cert.domain_names.length - 1 })}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge status={cert.status} />
                    {cert.error_message && (
                      <div className="text-xs text-red-500 dark:text-red-400 mt-1" title={cert.error_message}>
                        {t('list.error')}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <ProviderBadge provider={cert.provider} />
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {formatDate(cert.expires_at)}
                  </td>
                  <td className="px-6 py-4">
                    {cert.days_until_expiry !== undefined && cert.days_until_expiry >= 0 ? (
                      <span
                        className={`text-sm font-medium ${cert.days_until_expiry <= 30
                          ? 'text-red-600 dark:text-red-400'
                          : cert.days_until_expiry <= 60
                            ? 'text-yellow-600 dark:text-yellow-400'
                            : 'text-green-600 dark:text-green-400'
                          }`}
                      >
                        {t('list.days', { count: cert.days_until_expiry })}
                      </span>
                    ) : (
                      <span className="text-sm text-slate-400">-</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right space-x-2">
                    <button
                      onClick={() => setSelectedCertId(cert.id)}
                      className="text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-300 text-sm font-medium"
                    >
                      {t('list.view')}
                    </button>
                    {cert.status === 'issued' && cert.provider !== 'custom' && (
                      <button
                        onClick={() => handleRenew(cert)}
                        disabled={renewMutation.isPending}
                        className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium"
                      >
                        {t('list.renew')}
                      </button>
                    )}
                    {cert.status === 'issued' && (
                      <button
                        onClick={() => handleDownload(cert.id)}
                        disabled={downloadingCertId === cert.id}
                        className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300 text-sm font-medium"
                      >
                        {downloadingCertId === cert.id ? t('list.downloading') : t('list.download')}
                      </button>
                    )}
                    <button
                      onClick={() => handleDelete(cert.id)}
                      disabled={deleteMutation.isPending}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium"
                    >
                      {t('list.delete')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Certificate Detail Modal */}
      {selectedCertId && (
        <CertificateDetail
          certificateId={selectedCertId}
          onClose={() => setSelectedCertId(null)}
        />
      )}

      {/* Renewal Log Modal */}
      {showRenewLogModal && renewingCertId && (
        <CertificateLogModal
          certificateId={renewingCertId}
          onClose={handleRenewLogModalClose}
          title={t('renewal.title', '인증서 갱신')}
          subtitle={t('renewal.subtitle', '실시간 갱신 로그')}
        />
      )}
    </div>
  );
}

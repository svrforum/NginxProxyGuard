import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import React, { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { listCertificates, deleteCertificate, renewCertificate, downloadCertificate, bulkDeleteErrorCertificates, clearCertificateError } from '../api/certificates';
import { fetchProxyHosts } from '../api/proxy-hosts';
import type { Certificate } from '../types/certificate';
import CertificateForm from './CertificateForm';
import CertificateUpdateForm from './CertificateUpdateForm';
import { CertificateDetail } from './CertificateDetail';
import { CertificateLogModal } from './CertificateLogModal';
import CertificateFilters from './certificate/CertificateFilters';
import CertificatePagination from './certificate/CertificatePagination';
import { StatusBadge, ProviderBadge, LinkedHostsCell, DomainCell } from './certificate/CertificateBadges';

type SortOption = 'created-desc' | 'created-asc' | 'expires-asc' | 'expires-desc' | 'domain-asc' | 'domain-desc';

function parseSortOption(option: SortOption): { sortBy: string; sortOrder: string } {
  const [sortBy, sortOrder] = option.split('-');
  return { sortBy, sortOrder };
}

export default function CertificateList() {
  const { t, i18n } = useTranslation('certificates');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState<string | null>(null);
  const [renewingCertId, setRenewingCertId] = useState<string | null>(null);
  const [showRenewLogModal, setShowRenewLogModal] = useState(false);
  const [downloadingCertId, setDownloadingCertId] = useState<string | null>(null);
  const [updatingCertId, setUpdatingCertId] = useState<string | null>(null);

  // Search state
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== searchQuery) {
        setSearchQuery(searchInput);
        setCurrentPage(1);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchInput, searchQuery]);

  const [perPage, setPerPage] = useState<number>(() => {
    const saved = localStorage.getItem('certPerPage');
    return saved ? parseInt(saved, 10) : 20;
  });

  const [sortOption, setSortOption] = useState<SortOption>(() => {
    const saved = localStorage.getItem('certSortOption');
    return (saved as SortOption) || 'created-desc';
  });

  const [statusFilter, setStatusFilter] = useState('');
  const [providerFilter, setProviderFilter] = useState('');

  const { sortBy, sortOrder } = parseSortOption(sortOption);

  const { data, isLoading, error } = useQuery({
    queryKey: ['certificates', currentPage, perPage, searchQuery, sortBy, sortOrder, statusFilter, providerFilter],
    queryFn: () => listCertificates(currentPage, perPage, searchQuery, sortBy, sortOrder, statusFilter, providerFilter),
    refetchInterval: 5000,
  });

  const { data: proxyHostsData } = useQuery({
    queryKey: ['proxy-hosts-for-certs'],
    queryFn: () => fetchProxyHosts(1, 200),
    staleTime: 30000,
  });

  const hostsByCertId = useMemo(() => (proxyHostsData?.data ?? []).reduce((map, h) => {
    if (h.certificate_id) (map[h.certificate_id] ??= []).push({ domain: h.domain_names[0], enabled: h.enabled });
    return map;
  }, {} as Record<string, { domain: string; enabled: boolean }[]>), [proxyHostsData]);

  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 1;
  const hasFilters = searchQuery || statusFilter || providerFilter;
  const hasErrorCerts = data?.data?.some(c => c.status === 'error') || statusFilter === 'error';

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

  const clearErrorMutation = useMutation({
    mutationFn: clearCertificateError,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });

  const bulkDeleteMutation = useMutation({
    mutationFn: bulkDeleteErrorCertificates,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      alert(t('messages.bulkDeleteSuccess', { count: result.deleted }));
    },
    onError: () => {
      alert(t('messages.bulkDeleteFailed'));
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('messages.deleteConfirm'))) {
      deleteMutation.mutate(id);
    }
  };

  const handleBulkDeleteErrors = () => {
    if (confirm(t('messages.bulkDeleteConfirm'))) {
      bulkDeleteMutation.mutate();
    }
  };

  const handleRenew = async (cert: Certificate) => {
    if (!confirm(t('messages.renewConfirm'))) return;

    if (cert.provider === 'letsencrypt') {
      try {
        await renewMutation.mutateAsync(cert.id);
      } catch {
        // Ignore error, will be shown in modal
      }
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

  const handlePerPageChange = (value: number) => { setPerPage(value); localStorage.setItem('certPerPage', String(value)); setCurrentPage(1); };

  const handleSortChange = (value: SortOption) => { setSortOption(value); localStorage.setItem('certSortOption', value); setCurrentPage(1); };

  const handleClearSearch = () => { setSearchInput(''); setSearchQuery(''); setCurrentPage(1); };

  const formatDate = (d?: string) => d ? new Date(d).toLocaleDateString(i18n.language) : '-';

  if (isLoading && !data) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
        {t('messages.loadError')}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('title')}</h2>
        <div className="flex items-center gap-2">
          {hasErrorCerts && (
            <button
              onClick={handleBulkDeleteErrors}
              disabled={bulkDeleteMutation.isPending}
              className="px-3 py-2 text-sm font-medium text-red-600 dark:text-red-400 border border-red-300 dark:border-red-700 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 transition-colors"
            >
              {t('list.bulkDeleteErrors')}
            </button>
          )}
          <button
            onClick={() => setShowForm(true)}
            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            + {t('list.actionNew')}
          </button>
        </div>
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

      {/* Search and Filters */}
      <CertificateFilters
        searchInput={searchInput}
        setSearchInput={setSearchInput}
        onClearSearch={handleClearSearch}
        statusFilter={statusFilter}
        setStatusFilter={setStatusFilter}
        providerFilter={providerFilter}
        setProviderFilter={setProviderFilter}
        sortOption={sortOption}
        onSortChange={handleSortChange}
        onPageReset={() => setCurrentPage(1)}
      />

      {/* Table */}
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
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('detail.linkedHosts')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {hasFilters ? t('list.noResults') : t('list.empty')}
                </td>
              </tr>
            ) : (
              data?.data?.map((cert) => {
                const hasRenewalFailure = cert.status === 'issued' && !!cert.error_message;
                return (
                  <React.Fragment key={cert.id}>
                    {/* Main certificate row */}
                    <tr className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                      <td className="px-6 py-4">
                        <DomainCell domains={cert.domain_names} />
                      </td>
                      <td className="px-6 py-4">
                        <StatusBadge status={cert.status} />
                        {cert.status === 'error' && cert.error_message && (
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
                          <span className={`text-sm font-medium ${cert.days_until_expiry <= 30 ? 'text-red-600 dark:text-red-400' : cert.days_until_expiry <= 60 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'}`}>
                            {t('list.days', { count: cert.days_until_expiry })}
                          </span>
                        ) : (
                          <span className="text-sm text-slate-400">-</span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <LinkedHostsCell hosts={hostsByCertId[cert.id]} />
                      </td>
                      <td className="px-6 py-4 text-right space-x-2 whitespace-nowrap">
                        <button onClick={() => setSelectedCertId(cert.id)} className="text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-300 text-sm font-medium">{t('list.view')}</button>
                        {cert.status === 'issued' && cert.provider === 'custom' && (
                          <button onClick={() => setUpdatingCertId(cert.id)} className="text-amber-600 hover:text-amber-900 dark:text-amber-400 dark:hover:text-amber-300 text-sm font-medium">{t('list.update')}</button>
                        )}
                        {cert.status === 'issued' && cert.provider !== 'custom' && (
                          <button onClick={() => handleRenew(cert)} disabled={renewMutation.isPending} className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium">{t('list.renew')}</button>
                        )}
                        {cert.status === 'issued' && (
                          <button onClick={() => handleDownload(cert.id)} disabled={downloadingCertId === cert.id} className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300 text-sm font-medium">{downloadingCertId === cert.id ? t('list.downloading') : t('list.download')}</button>
                        )}
                        <button onClick={() => handleDelete(cert.id)} disabled={deleteMutation.isPending} className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium">{t('list.delete')}</button>
                      </td>
                    </tr>
                    {/* Renewal failure sub-row */}
                    {hasRenewalFailure && (
                      <tr className="bg-amber-50/50 dark:bg-amber-900/10">
                        <td className="px-6 py-2 pl-10">
                          <span className="text-xs text-amber-700 dark:text-amber-400">↳ {cert.domain_names[0]}</span>
                        </td>
                        <td className="px-6 py-2 whitespace-nowrap">
                          <span className="px-2 py-1 text-xs font-medium rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300">
                            {t('list.renewalFailed')}
                          </span>
                        </td>
                        <td colSpan={3} className="px-6 py-2">
                          <span className="text-xs text-amber-700 dark:text-amber-400 break-words line-clamp-2" title={cert.error_message}>
                            {cert.error_message}
                          </span>
                        </td>
                        <td className="px-6 py-2">&nbsp;</td>
                        <td className="px-6 py-2 text-right">
                          <button
                            onClick={() => clearErrorMutation.mutate(cert.id)}
                            disabled={clearErrorMutation.isPending}
                            className="text-amber-700 hover:text-amber-900 dark:text-amber-400 dark:hover:text-amber-300 text-xs font-medium"
                          >
                            {t('list.dismissError')}
                          </button>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <CertificatePagination
        currentPage={currentPage}
        totalPages={totalPages}
        total={total}
        perPage={perPage}
        onPageChange={setCurrentPage}
        onPerPageChange={handlePerPageChange}
      />

      {/* Certificate Detail Modal */}
      {selectedCertId && (
        <CertificateDetail
          certificateId={selectedCertId}
          onClose={() => setSelectedCertId(null)}
        />
      )}

      {/* Certificate Update Modal */}
      {updatingCertId && (
        <CertificateUpdateForm
          certificateId={updatingCertId}
          onClose={() => setUpdatingCertId(null)}
          onSuccess={() => {
            setUpdatingCertId(null);
            queryClient.invalidateQueries({ queryKey: ['certificates'] });
          }}
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

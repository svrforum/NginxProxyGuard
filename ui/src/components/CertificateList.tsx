import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { listCertificates, deleteCertificate, renewCertificate, downloadCertificate, bulkDeleteErrorCertificates } from '../api/certificates';
import type { Certificate } from '../types/certificate';
import CertificateForm from './CertificateForm';
import CertificateUpdateForm from './CertificateUpdateForm';
import { CertificateDetail } from './CertificateDetail';
import { CertificateLogModal } from './CertificateLogModal';

const PER_PAGE_OPTIONS = [10, 20, 50, 100];

type SortOption = 'created-desc' | 'created-asc' | 'expires-asc' | 'expires-desc' | 'domain-asc' | 'domain-desc';

function parseSortOption(option: SortOption): { sortBy: string; sortOrder: string } {
  const [sortBy, sortOrder] = option.split('-');
  return { sortBy, sortOrder };
}

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

  const total = data?.total ?? 0;
  const totalPages = data?.total_pages ?? 1;
  const hasFilters = searchQuery || statusFilter || providerFilter;

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

  const handlePerPageChange = (value: number) => {
    setPerPage(value);
    localStorage.setItem('certPerPage', String(value));
    setCurrentPage(1);
  };

  const handleSortChange = (value: SortOption) => {
    setSortOption(value);
    localStorage.setItem('certSortOption', value);
    setCurrentPage(1);
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString(i18n.language);
  };

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
          <button
            onClick={handleBulkDeleteErrors}
            disabled={bulkDeleteMutation.isPending}
            className="px-3 py-2 text-sm font-medium text-red-600 dark:text-red-400 border border-red-300 dark:border-red-700 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 transition-colors"
          >
            {t('list.bulkDeleteErrors')}
          </button>
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
      <div className="flex flex-col sm:flex-row gap-3">
        {/* Search */}
        <div className="relative flex-1">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder={t('list.search')}
            className="w-full pl-10 pr-8 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
          {searchInput && (
            <button
              onClick={() => { setSearchInput(''); setSearchQuery(''); setCurrentPage(1); }}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }}
          className="px-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        >
          <option value="">{t('list.filter.allStatus')}</option>
          <option value="issued">{t('certStatuses.issued')}</option>
          <option value="pending">{t('certStatuses.pending')}</option>
          <option value="expired">{t('certStatuses.expired')}</option>
          <option value="error">{t('certStatuses.error')}</option>
          <option value="renewing">{t('certStatuses.renewing')}</option>
        </select>

        {/* Provider Filter */}
        <select
          value={providerFilter}
          onChange={(e) => { setProviderFilter(e.target.value); setCurrentPage(1); }}
          className="px-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        >
          <option value="">{t('list.filter.allProvider')}</option>
          <option value="letsencrypt">{t('certProviders.letsencrypt')}</option>
          <option value="selfsigned">{t('certProviders.selfsigned')}</option>
          <option value="custom">{t('certProviders.custom')}</option>
        </select>

        {/* Sort */}
        <select
          value={sortOption}
          onChange={(e) => handleSortChange(e.target.value as SortOption)}
          className="px-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        >
          <option value="created-desc">{t('list.sort.createdDesc')}</option>
          <option value="created-asc">{t('list.sort.createdAsc')}</option>
          <option value="expires-asc">{t('list.sort.expiresAsc')}</option>
          <option value="expires-desc">{t('list.sort.expiresDesc')}</option>
          <option value="domain-asc">{t('list.sort.domainAsc')}</option>
          <option value="domain-desc">{t('list.sort.domainDesc')}</option>
        </select>
      </div>

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
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {hasFilters ? t('list.noResults') : t('list.empty')}
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
                    {cert.status === 'issued' && cert.provider === 'custom' && (
                      <button
                        onClick={() => setUpdatingCertId(cert.id)}
                        className="text-amber-600 hover:text-amber-900 dark:text-amber-400 dark:hover:text-amber-300 text-sm font-medium"
                      >
                        {t('list.update')}
                      </button>
                    )}
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

      {/* Pagination */}
      {total > 0 && (
        <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="text-sm text-slate-500 dark:text-slate-400">
              {t('list.showing', {
                from: (currentPage - 1) * perPage + 1,
                to: Math.min(currentPage * perPage, total),
                total
              })}
            </div>
            <div className="flex items-center gap-2">
              <select
                value={perPage}
                onChange={(e) => handlePerPageChange(Number(e.target.value))}
                className="px-2 py-1 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              >
                {PER_PAGE_OPTIONS.map(option => (
                  <option key={option} value={option}>{t('list.perPage', { count: option })}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {/* First Page */}
            <button
              onClick={() => setCurrentPage(1)}
              disabled={currentPage === 1}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.first')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
              </svg>
            </button>
            {/* Previous Page */}
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.previous')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </button>

            {/* Page Numbers */}
            <div className="flex items-center gap-1 px-2">
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum: number;
                if (totalPages <= 5) {
                  pageNum = i + 1;
                } else if (currentPage <= 3) {
                  pageNum = i + 1;
                } else if (currentPage >= totalPages - 2) {
                  pageNum = totalPages - 4 + i;
                } else {
                  pageNum = currentPage - 2 + i;
                }
                return (
                  <button
                    key={pageNum}
                    onClick={() => setCurrentPage(pageNum)}
                    className={`min-w-[32px] h-8 px-2 text-sm font-medium rounded-lg transition-colors ${
                      currentPage === pageNum
                        ? 'bg-primary-600 text-white'
                        : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700'
                    }`}
                  >
                    {pageNum}
                  </button>
                );
              })}
            </div>

            {/* Next Page */}
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.next')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
            {/* Last Page */}
            <button
              onClick={() => setCurrentPage(totalPages)}
              disabled={currentPage === totalPages}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              title={t('list.pagination.last')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M5 5l7 7-7 7" />
              </svg>
            </button>
          </div>
        </div>
      )}

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

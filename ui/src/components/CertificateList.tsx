import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useEffect, useMemo } from 'react';
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
import { IconButton, AddButton, EmptyState, EntityCard, PencilIcon, TrashIcon, ChevronRightIcon, DownloadIcon, RenewIcon, EyeIcon } from './common/listui';

type SortOption = 'created-desc' | 'created-asc' | 'expires-asc' | 'expires-desc' | 'domain-asc' | 'domain-desc';

function parseSortOption(option: SortOption): { sortBy: string; sortOrder: string } {
  const [sortBy, sortOrder] = option.split('-');
  return { sortBy, sortOrder };
}

interface CertificateCardProps {
  cert: Certificate;
  hosts?: { domain: string; enabled: boolean }[];
  expanded: boolean;
  onToggleExpand: () => void;
  onView: () => void;
  onUpdate: () => void;
  onRenew: () => void;
  onDownload: () => void;
  onDelete: () => void;
  onDismissError: () => void;
  downloading: boolean;
  renewPending: boolean;
  deletePending: boolean;
  dismissPending: boolean;
  formatDate: (d?: string) => string;
}

function CertificateCard({
  cert, hosts, expanded, onToggleExpand, onView, onUpdate, onRenew, onDownload, onDelete,
  onDismissError, downloading, renewPending, deletePending, dismissPending, formatDate,
}: CertificateCardProps) {
  const { t } = useTranslation(['certificates', 'common']);
  const hasRenewalFailure = cert.status === 'issued' && !!cert.error_message;
  const days = cert.days_until_expiry;
  const daysClass = days === undefined || days < 0
    ? 'text-slate-400'
    : days <= 30 ? 'text-red-600 dark:text-red-400'
      : days <= 60 ? 'text-yellow-600 dark:text-yellow-400'
        : 'text-green-600 dark:text-green-400';

  return (
    <EntityCard active={hasRenewalFailure && expanded}>
      <div className="flex items-start gap-3 px-4 py-3.5 sm:px-5">
        {/* Left: domains + status + provider + expiry */}
        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <DomainCell domains={cert.domain_names} />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={cert.status} />
            <ProviderBadge provider={cert.provider} />
            {cert.status === 'error' && cert.error_message && (
              <span className="text-xs text-red-500 dark:text-red-400" title={cert.error_message}>
                {t('list.error')}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
            <span className="whitespace-nowrap">
              {t('list.expires')}: {formatDate(cert.expires_at)}
            </span>
            {days !== undefined && days >= 0 && (
              <span className={`font-medium whitespace-nowrap ${daysClass}`}>
                {t('list.days', { count: days })}
              </span>
            )}
            {hosts?.length ? (
              <span className="inline-flex items-center gap-2">
                <span className="text-slate-400 dark:text-slate-500">{t('detail.linkedHosts')}:</span>
                <LinkedHostsCell hosts={hosts} />
              </span>
            ) : null}
          </div>
        </div>

        {/* Right: action icon buttons */}
        <div className="flex shrink-0 items-center gap-0.5">
          <IconButton onClick={onView} title={t('list.view')}>
            <EyeIcon />
          </IconButton>
          {cert.status === 'issued' && cert.provider === 'custom' && (
            <IconButton onClick={onUpdate} title={t('list.update')}>
              <PencilIcon />
            </IconButton>
          )}
          {cert.status === 'issued' && cert.provider !== 'custom' && (
            <IconButton onClick={onRenew} title={t('list.renew')} disabled={renewPending}>
              <RenewIcon />
            </IconButton>
          )}
          {cert.status === 'issued' && (
            <IconButton onClick={onDownload} title={downloading ? t('list.downloading') : t('list.download')} disabled={downloading}>
              <DownloadIcon />
            </IconButton>
          )}
          <IconButton onClick={onDelete} title={t('list.delete')} variant="danger" disabled={deletePending}>
            <TrashIcon />
          </IconButton>
        </div>
      </div>

      {/* Renewal-failure disclosure */}
      {hasRenewalFailure && (
        <>
          <button
            type="button"
            onClick={onToggleExpand}
            aria-expanded={expanded}
            className="flex w-full items-center gap-2 border-t border-amber-200/60 dark:border-amber-800/40 bg-amber-50/60 dark:bg-amber-900/10 px-4 py-2 text-left text-xs font-medium text-amber-700 dark:text-amber-400 transition-colors hover:bg-amber-50 dark:hover:bg-amber-900/20 sm:px-5"
          >
            <ChevronRightIcon className={`h-3.5 w-3.5 shrink-0 transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`} />
            {t('list.renewalFailed')}
          </button>
          <div className={`grid transition-[grid-template-rows] duration-200 ease-out ${expanded ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
            <div className="overflow-hidden">
              <div className="flex items-start justify-between gap-3 border-t border-amber-200/40 dark:border-amber-800/30 bg-amber-50/40 dark:bg-amber-900/5 px-4 py-3 sm:px-5">
                <p className="break-words text-xs text-amber-700 dark:text-amber-400" title={cert.error_message}>
                  {cert.error_message}
                </p>
                <button
                  onClick={onDismissError}
                  disabled={dismissPending}
                  className="shrink-0 text-xs font-medium text-amber-700 hover:text-amber-900 dark:text-amber-400 dark:hover:text-amber-300 disabled:opacity-50"
                >
                  {t('list.dismissError')}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </EntityCard>
  );
}

export default function CertificateList() {
  const { t, i18n } = useTranslation(['certificates', 'common']);
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState<string | null>(null);
  const [renewingCertId, setRenewingCertId] = useState<string | null>(null);
  const [showRenewLogModal, setShowRenewLogModal] = useState(false);
  const [downloadingCertId, setDownloadingCertId] = useState<string | null>(null);
  const [updatingCertId, setUpdatingCertId] = useState<string | null>(null);
  const [expandedCertId, setExpandedCertId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

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
    refetchInterval: 120000,
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
      setNotice({ type: 'success', message: t('messages.bulkDeleteSuccess', { count: result.deleted }) });
    },
    onError: () => {
      setNotice({ type: 'error', message: t('messages.bulkDeleteFailed') });
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
      setNotice({ type: 'error', message: err instanceof Error ? err.message : t('messages.downloadError') });
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
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
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
          <AddButton onClick={() => setShowForm(true)}>{t('list.actionNew')}</AddButton>
        </div>
      </div>

      {/* Inline result notice (bulk delete / download) */}
      {notice && (
        <div
          className={`flex items-start justify-between gap-3 px-4 py-3 rounded-lg border text-sm ${
            notice.type === 'success'
              ? 'bg-green-50 dark:bg-green-900/30 border-green-200 dark:border-green-800 text-green-700 dark:text-green-400'
              : 'bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-400'
          }`}
        >
          <span className="break-words">{notice.message}</span>
          <button
            onClick={() => setNotice(null)}
            aria-label={t('common:buttons.close')}
            className="flex-shrink-0 opacity-70 hover:opacity-100 transition-opacity"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

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

      {/* Card list */}
      {data?.data?.length === 0 ? (
        <EmptyState
          icon={
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          }
        >
          {hasFilters ? t('list.noResults') : t('list.empty')}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {data?.data?.map((cert) => (
            <CertificateCard
              key={cert.id}
              cert={cert}
              hosts={hostsByCertId[cert.id]}
              expanded={expandedCertId === cert.id}
              onToggleExpand={() => setExpandedCertId(expandedCertId === cert.id ? null : cert.id)}
              onView={() => setSelectedCertId(cert.id)}
              onUpdate={() => setUpdatingCertId(cert.id)}
              onRenew={() => handleRenew(cert)}
              onDownload={() => handleDownload(cert.id)}
              onDelete={() => handleDelete(cert.id)}
              onDismissError={() => clearErrorMutation.mutate(cert.id)}
              downloading={downloadingCertId === cert.id}
              renewPending={renewMutation.isPending}
              deletePending={deleteMutation.isPending}
              dismissPending={clearErrorMutation.isPending}
              formatDate={formatDate}
            />
          ))}
        </div>
      )}

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

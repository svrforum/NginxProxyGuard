import { useTranslation } from 'react-i18next';

type SortOption = 'created-desc' | 'created-asc' | 'expires-asc' | 'expires-desc' | 'domain-asc' | 'domain-desc';

interface CertificateFiltersProps {
  searchInput: string;
  setSearchInput: (value: string) => void;
  onClearSearch: () => void;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  providerFilter: string;
  setProviderFilter: (value: string) => void;
  sortOption: SortOption;
  onSortChange: (value: SortOption) => void;
  onPageReset: () => void;
}

export default function CertificateFilters({
  searchInput,
  setSearchInput,
  onClearSearch,
  statusFilter,
  setStatusFilter,
  providerFilter,
  setProviderFilter,
  sortOption,
  onSortChange,
  onPageReset,
}: CertificateFiltersProps) {
  const { t } = useTranslation('certificates');

  return (
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
            onClick={onClearSearch}
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
        onChange={(e) => { setStatusFilter(e.target.value); onPageReset(); }}
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
        onChange={(e) => { setProviderFilter(e.target.value); onPageReset(); }}
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
        onChange={(e) => onSortChange(e.target.value as SortOption)}
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
  );
}

import { useTranslation } from 'react-i18next';

export type SortBy = 'name' | 'updated' | 'created';
export type SortOrder = 'asc' | 'desc';

interface ProxyHostFiltersProps {
  searchInput: string;
  onSearchChange: (value: string) => void;
  onClearSearch: () => void;
  sortBy: SortBy;
  sortOrder: SortOrder;
  onSortChange: (sortBy: SortBy, sortOrder: SortOrder) => void;
  onAdd: () => void;
}

export function ProxyHostFilters({
  searchInput,
  onSearchChange,
  onClearSearch,
  sortBy,
  sortOrder,
  onSortChange,
  onAdd,
}: ProxyHostFiltersProps) {
  const { t } = useTranslation('proxyHost');

  return (
    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4">
      <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('list.title')}</h2>

      <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
        {/* Search */}
        <div className="relative flex-1 sm:flex-none">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={searchInput}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder={t('list.search')}
            className="w-full sm:w-48 pl-9 pr-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
          {searchInput && (
            <button
              onClick={onClearSearch}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-400"
            >
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {/* Sort */}
        <select
          value={`${sortBy}-${sortOrder}`}
          onChange={(e) => {
            const [by, order] = e.target.value.split('-') as [SortBy, SortOrder];
            onSortChange(by, order);
          }}
          className="px-3 py-2 text-sm border border-slate-200 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
        >
          <option value="name-asc">{t('list.sort.nameAsc')}</option>
          <option value="name-desc">{t('list.sort.nameDesc')}</option>
          <option value="updated-desc">{t('list.sort.updatedDesc')}</option>
          <option value="updated-asc">{t('list.sort.updatedAsc')}</option>
          <option value="created-desc">{t('list.sort.createdDesc')}</option>
          <option value="created-asc">{t('list.sort.createdAsc')}</option>
        </select>

        <button
          onClick={onAdd}
          className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          {t('list.addNew')}
        </button>
      </div>
    </div>
  );
}

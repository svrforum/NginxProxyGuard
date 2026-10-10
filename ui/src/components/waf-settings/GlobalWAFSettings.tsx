import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  fetchGlobalWAFRules,
  fetchGlobalWAFPolicyHistory,
  disableGlobalWAFRule,
  enableGlobalWAFRule,
} from '../../api/waf';
import type {
  GlobalWAFRule,
  GlobalWAFRuleCategory,
  GlobalWAFPolicyHistory,
} from '../../types/waf';
import { CategoryIcon } from './CategoryIcon';

export function GlobalWAFSettings() {
  const { t, i18n } = useTranslation('waf');
  const [activeTab, setActiveTab] = useState<'rules' | 'history'>('rules');
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showDisabledOnly, setShowDisabledOnly] = useState(false);
  const queryClient = useQueryClient();

  const rulesQuery = useQuery({
    queryKey: ['global-waf-rules'],
    queryFn: fetchGlobalWAFRules,
  });

  const historyQuery = useQuery({
    queryKey: ['global-waf-policy-history'],
    queryFn: () => fetchGlobalWAFPolicyHistory(100),
    enabled: activeTab === 'history',
  });

  const disableMutation = useMutation({
    mutationFn: ({ ruleId, category, description, reason }: {
      ruleId: number;
      category?: string;
      description?: string;
      reason?: string;
    }) =>
      disableGlobalWAFRule(ruleId, {
        rule_id: ruleId,
        rule_category: category,
        rule_description: description,
        reason: reason,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-waf-rules'] });
      queryClient.invalidateQueries({ queryKey: ['global-waf-policy-history'] });
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] });
      queryClient.invalidateQueries({ queryKey: ['waf-hosts'] });
    },
  });

  const enableMutation = useMutation({
    mutationFn: (ruleId: number) => enableGlobalWAFRule(ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-waf-rules'] });
      queryClient.invalidateQueries({ queryKey: ['global-waf-policy-history'] });
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] });
      queryClient.invalidateQueries({ queryKey: ['waf-hosts'] });
    },
  });

  const [disableModalRule, setDisableModalRule] = useState<{
    rule: GlobalWAFRule;
    categoryName: string;
  } | null>(null);
  const [disableReason, setDisableReason] = useState('');

  const handleToggleRule = (rule: GlobalWAFRule, categoryName: string) => {
    if (!rule.globally_disabled) {
      setDisableModalRule({ rule, categoryName });
      setDisableReason('');
    } else {
      enableMutation.mutate(rule.id);
    }
  };

  const handleConfirmDisable = () => {
    if (!disableModalRule) return;
    disableMutation.mutate({
      ruleId: disableModalRule.rule.id,
      category: disableModalRule.categoryName,
      description: disableModalRule.rule.description,
      reason: disableReason.trim() || undefined,
    });
    setDisableModalRule(null);
    setDisableReason('');
  };

  const filteredData = useMemo(() => {
    if (!rulesQuery.data) return { categories: [], totalRules: 0, disabledRules: 0 };
    const query = searchQuery.toLowerCase();
    let totalRules = 0;
    let disabledRules = 0;
    if (!rulesQuery.data.categories) {
      return { categories: [], totalRules: 0, disabledRules: 0 };
    }
    const categories = rulesQuery.data.categories
      .map((cat) => {
        let rules = cat.rules || [];
        if (query) {
          rules = rules.filter(
            (r) => r.id.toString().includes(query) || r.description?.toLowerCase().includes(query)
          );
        }
        if (showDisabledOnly) {
          rules = rules.filter((r) => r.globally_disabled);
        }
        totalRules += rules.length;
        disabledRules += rules.filter((r) => r.globally_disabled).length;
        return { ...cat, rules };
      })
      .filter((cat) => {
        if (activeCategory === 'all') return cat.rules && cat.rules.length > 0;
        return cat.id === activeCategory;
      });
    return { categories, totalRules, disabledRules };
  }, [rulesQuery.data, searchQuery, showDisabledOnly, activeCategory]);

  const isPending = disableMutation.isPending || enableMutation.isPending;

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString(i18n.language, {
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    });
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border dark:border-slate-700 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b dark:border-slate-700 bg-gray-50 dark:bg-slate-900">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 flex items-center justify-center">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{t('global.title')}</h2>
            <p className="text-sm text-gray-500 dark:text-slate-400">
              {t('global.ruleCount', { total: rulesQuery.data?.total_rules || 0, disabled: rulesQuery.data?.global_exclusions?.length || 0 })}
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="px-6 border-b dark:border-slate-700 bg-white dark:bg-slate-800">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('rules')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${activeTab === 'rules'
              ? 'border-blue-600 dark:border-blue-500 text-blue-600 dark:text-blue-500'
              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'
            }`}
          >
            {t('policyManager.tabs.rules')}
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${activeTab === 'history'
              ? 'border-blue-600 dark:border-blue-500 text-blue-600 dark:text-blue-500'
              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'
            }`}
          >
            {t('policyManager.tabs.history')}
          </button>
        </div>
      </div>

      {activeTab === 'rules' ? (
        <>
          {/* Toolbar */}
          <div className="px-6 py-3 border-b dark:border-slate-700 bg-white dark:bg-slate-800 flex flex-wrap items-center gap-3">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <input
                  type="text"
                  placeholder={t('policyManager.searchPlaceholder')}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-white dark:placeholder-slate-400"
                />
              </div>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={showDisabledOnly} onChange={(e) => setShowDisabledOnly(e.target.checked)} className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500" />
              <span className="text-sm text-gray-600 dark:text-slate-300">{t('global.showDisabledOnly')}</span>
            </label>
            <div className="text-sm text-gray-500 dark:text-slate-400">
              {t('policyManager.showingCount', { count: filteredData.totalRules })}
              {filteredData.disabledRules > 0 && (
                <span className="text-purple-600 dark:text-purple-400 ml-1">
                  {t('global.globallyDisabled', { count: filteredData.disabledRules })}
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-col md:flex-row" style={{ height: '600px' }}>
            {/* Category Sidebar */}
            <div className="w-full md:w-48 h-auto md:h-full flex-shrink-0 border-b md:border-b-0 md:border-r border-slate-200 dark:border-slate-700 bg-gray-50 dark:bg-slate-900 overflow-x-auto md:overflow-y-auto flex md:block scrollbar-hide">
              <div className="flex md:block p-2 gap-2 min-w-max">
                <button
                  onClick={() => setActiveCategory('all')}
                  className={`w-auto md:w-full whitespace-nowrap px-3 py-2 text-left rounded-lg text-sm transition-colors ${activeCategory === 'all' ? 'bg-blue-600 text-white' : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-700 dark:text-slate-300'}`}
                >
                  {t('policyManager.allCategories')}
                </button>
                {rulesQuery.data?.categories?.map((cat) => {
                  const disabledCount = cat.rules?.filter((r) => r.globally_disabled).length || 0;
                  return (
                    <button
                      key={cat.id}
                      onClick={() => setActiveCategory(cat.id)}
                      className={`w-auto md:w-full whitespace-nowrap px-3 py-2 text-left rounded-lg text-sm transition-colors mt-0 md:mt-1 ${activeCategory === cat.id ? 'bg-blue-600 text-white' : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-700 dark:text-slate-300'}`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="truncate">{cat.name}</span>
                        {disabledCount > 0 && (
                          <span className={`ml-1 px-1.5 py-0.5 text-xs rounded ${activeCategory === cat.id ? 'bg-blue-500 text-white' : 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400'}`}>
                            {disabledCount}
                          </span>
                        )}
                      </div>
                      <div className={`text-xs ${activeCategory === cat.id ? 'text-blue-200' : 'text-gray-500 dark:text-slate-500'}`}>
                        {t('policyManager.ruleCount', { count: cat.rule_count })}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Rules List */}
            <div className="flex-1 overflow-y-auto">
              {rulesQuery.isLoading ? (
                <div className="flex items-center justify-center h-full">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
              ) : rulesQuery.error ? (
                <div className="p-6 text-center text-red-600">{t('policyManager.loadError')}</div>
              ) : filteredData.categories.length === 0 ? (
                <div className="p-6 text-center text-gray-500 dark:text-slate-400">
                  {searchQuery ? t('policyManager.noResults') : t('policyManager.empty')}
                </div>
              ) : (
                <div className="divide-y">
                  {filteredData.categories.map((category) => (
                    <GlobalCategoryRulesSection
                      key={category.id}
                      category={category}
                      onToggleRule={(rule) => handleToggleRule(rule, category.name)}
                      isPending={isPending}
                      showCategoryHeader={activeCategory === 'all'}
                      formatDate={formatDate}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      ) : (
        <div style={{ height: '600px' }} className="flex flex-col overflow-hidden">
          <GlobalPolicyHistoryPanel
            history={historyQuery.data?.history || []}
            isLoading={historyQuery.isLoading}
            error={historyQuery.error}
          />
        </div>
      )}

      {/* Disable Reason Modal */}
      {disableModalRule && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setDisableModalRule(null)} />
          <div className="relative bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
            <div className="px-6 py-4 border-b dark:border-slate-700 bg-purple-50 dark:bg-purple-900/20">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{t('global.disableModal.title')}</h3>
              <p className="text-sm text-purple-600 dark:text-purple-400 mt-1">{t('global.disableModal.warning')}</p>
            </div>
            <div className="p-6">
              <div className="mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400">{disableModalRule.rule.id}</span>
                  <span className="text-sm font-medium text-gray-700 dark:text-slate-300">{disableModalRule.categoryName}</span>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400">{disableModalRule.rule.description || t('policyManager.noDescription')}</p>
              </div>
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                  {t('disableModal.reasonLabel')} <span className="text-gray-400 dark:text-slate-500">({t('disableModal.optional')})</span>
                </label>
                <textarea
                  value={disableReason}
                  onChange={(e) => setDisableReason(e.target.value)}
                  placeholder={t('global.disableModal.reasonPlaceholder')}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-white dark:placeholder-slate-400 resize-none"
                  rows={3}
                  autoFocus
                />
              </div>
              <div className="flex gap-3 justify-end">
                <button onClick={() => setDisableModalRule(null)} className="px-4 py-2 text-sm text-gray-700 dark:text-slate-300 bg-gray-100 dark:bg-slate-700 rounded-lg hover:bg-gray-200 dark:hover:bg-slate-600 transition-colors">
                  {t('disableModal.cancel')}
                </button>
                <button onClick={handleConfirmDisable} disabled={disableMutation.isPending} className="px-4 py-2 text-sm text-white bg-purple-600 dark:bg-purple-500 rounded-lg hover:bg-purple-700 dark:hover:bg-purple-600 transition-colors disabled:opacity-50">
                  {disableMutation.isPending ? t('disableModal.processing') : t('global.disableModal.confirm')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function GlobalCategoryRulesSection({
  category, onToggleRule, isPending, showCategoryHeader, formatDate,
}: {
  category: GlobalWAFRuleCategory;
  onToggleRule: (rule: GlobalWAFRule) => void;
  isPending: boolean;
  showCategoryHeader: boolean;
  formatDate: (dateStr: string) => string;
}) {
  const { t } = useTranslation('waf');
  const [isExpanded, setIsExpanded] = useState(true);
  const enabledCount = category.rules?.filter((r) => !r.globally_disabled).length || 0;
  const disabledCount = (category.rules?.length || 0) - enabledCount;

  return (
    <div>
      {showCategoryHeader && (
        <div className="sticky top-0 bg-white dark:bg-slate-800 border-b dark:border-slate-700 px-4 py-3 flex items-center justify-between z-10">
          <button onClick={() => setIsExpanded(!isExpanded)} className="flex items-center gap-3">
            <CategoryIcon name={category.name} />
            <div className="text-left">
              <div className="font-semibold text-gray-900 dark:text-white">{category.name}</div>
              <div className="text-xs text-gray-500 dark:text-slate-400">
                {category.description} | {t('policyManager.ruleCount', { count: category.rules?.length || 0 })}
                {disabledCount > 0 && (
                  <span className="text-purple-600 dark:text-purple-400 ml-1">{t('global.globallyDisabled', { count: disabledCount })}</span>
                )}
              </div>
            </div>
            <svg className={`w-4 h-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
      )}
      {(!showCategoryHeader || isExpanded) && (
        <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
          {category.rules?.map((rule) => (
            <GlobalRuleRow key={rule.id} rule={rule} onToggle={() => onToggleRule(rule)} isPending={isPending} formatDate={formatDate} />
          ))}
        </div>
      )}
    </div>
  );
}

function GlobalRuleRow({ rule, onToggle, isPending, formatDate }: {
  rule: GlobalWAFRule; onToggle: () => void; isPending: boolean; formatDate: (dateStr: string) => string;
}) {
  const { t } = useTranslation('waf');
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div className={`${rule.globally_disabled ? 'bg-purple-50 dark:bg-purple-900/10' : 'bg-white dark:bg-slate-800'}`}>
      <div className="px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors cursor-pointer" onClick={() => rule.global_exclusion && setShowDetails(!showDetails)}>
        <div className="flex items-center gap-3 min-w-0">
          <span className={`px-2 py-0.5 rounded text-xs font-mono ${!rule.globally_disabled ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'}`}>{rule.id}</span>
          <span className="text-sm text-gray-700 dark:text-slate-300 truncate" title={rule.description}>{rule.description || t('policyManager.noDescription')}</span>
          {rule.globally_disabled && (
            <span className="px-1.5 py-0.5 text-xs rounded bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              {t('global.badge')}
            </span>
          )}
          {rule.global_exclusion && (
            <svg className={`w-4 h-4 text-gray-400 transition-transform ${showDetails ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
        <button onClick={(e) => { e.stopPropagation(); onToggle(); }} disabled={isPending}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 ${!rule.globally_disabled ? 'bg-green-500' : 'bg-gray-300'} ${isPending ? 'opacity-50 cursor-not-allowed' : ''}`}>
          <span className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${!rule.globally_disabled ? 'translate-x-5' : 'translate-x-0'}`} />
        </button>
      </div>
      {showDetails && rule.global_exclusion && (
        <div className="px-4 pb-3 ml-8 mr-4">
          <div className="bg-purple-100 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-900/40 rounded-lg p-3 text-sm">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
              <span className="font-semibold text-purple-800 dark:text-purple-300">{t('global.exclusionInfo')}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-purple-900 dark:text-purple-200">
              <div>
                <span className="text-purple-600 dark:text-purple-400 text-xs">{t('policyManager.disabledAt')}</span>
                <p className="font-medium">{formatDate(rule.global_exclusion.created_at)}</p>
              </div>
              {rule.global_exclusion.reason && (
                <div>
                  <span className="text-purple-600 dark:text-purple-400 text-xs">{t('policyManager.reason')}</span>
                  <p className="font-medium">{rule.global_exclusion.reason}</p>
                </div>
              )}
              {rule.global_exclusion.disabled_by && (
                <div>
                  <span className="text-purple-600 dark:text-purple-400 text-xs">{t('policyManager.disabledBy')}</span>
                  <p className="font-medium">{rule.global_exclusion.disabled_by}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function GlobalPolicyHistoryPanel({ history, isLoading, error }: {
  history: GlobalWAFPolicyHistory[]; isLoading: boolean; error: Error | null;
}) {
  const { t, i18n } = useTranslation('waf');
  const [historySearch, setHistorySearch] = useState('');

  const filteredHistory = useMemo(() => {
    if (!historySearch.trim()) return history;
    const query = historySearch.trim().toLowerCase();
    return history.filter((item) =>
      item.rule_id.toString().includes(query) || item.rule_category?.toLowerCase().includes(query) || item.rule_description?.toLowerCase().includes(query)
    );
  }, [history, historySearch]);

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString(i18n.language, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  if (isLoading) {
    return <div className="flex items-center justify-center h-full"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div></div>;
  }
  if (error) {
    return <div className="p-6 text-center text-red-600 dark:text-red-400">{t('global.history.loadError')}</div>;
  }

  return (
    <>
      <div className="flex-shrink-0 px-6 py-3 border-b dark:border-slate-700 bg-white dark:bg-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex-1 max-w-xs">
            <div className="relative">
              <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input type="text" placeholder={t('global.history.searchPlaceholder')} value={historySearch} onChange={(e) => setHistorySearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-white dark:placeholder-slate-400" />
            </div>
          </div>
          <div className="text-sm text-gray-500 dark:text-slate-400">
            {t('global.history.count', { count: filteredHistory.length })}
            {historySearch && history.length !== filteredHistory.length && (
              <span className="text-gray-400 dark:text-slate-500 ml-1">({t('global.history.total', { count: history.length })})</span>
            )}
          </div>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto">
        {filteredHistory.length === 0 ? (
          <div className="p-12 text-center text-gray-500 dark:text-slate-400">
            <svg className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-lg font-medium">{t('global.history.empty')}</p>
            <p className="text-sm mt-1">{t('global.history.emptyDescription')}</p>
          </div>
        ) : (
          <div className="divide-y">
            {filteredHistory.map((item) => (
              <div key={item.id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-slate-700/50">
                <div className="flex items-start gap-4">
                  <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${item.action === 'disabled' ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400' : 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400'}`}>
                    {item.action === 'disabled' ? (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
                    ) : (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded ${item.action === 'disabled' ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400' : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'}`}>
                        {item.action === 'disabled' ? t('global.history.disabled') : t('global.history.enabled')}
                      </span>
                      <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white">#{item.rule_id}</span>
                      {item.rule_category && <span className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 rounded">{item.rule_category}</span>}
                      <span className="px-1.5 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded flex items-center gap-1">
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                        {t('global.badge')}
                      </span>
                    </div>
                    {item.rule_description && <p className="text-sm text-gray-700 dark:text-slate-300 mb-1">{item.rule_description}</p>}
                    {item.reason && <p className="text-sm text-gray-500 dark:text-slate-400"><span className="font-medium">{t('global.history.reason')}:</span> {item.reason}</p>}
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-400 dark:text-slate-500">
                      <span>{formatDate(item.created_at)}</span>
                      {item.changed_by && <span>by {item.changed_by}</span>}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

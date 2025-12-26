import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  fetchWAFHostConfigs,
  fetchWAFRules,
  fetchWAFPolicyHistory,
  disableWAFRule,
  enableWAFRule,
  fetchGlobalWAFRules,
  fetchGlobalWAFPolicyHistory,
  disableGlobalWAFRule,
  enableGlobalWAFRule,
} from '../api/waf';
import type {
  WAFHostConfig,
  WAFRuleCategory,
  WAFRule,
  WAFPolicyHistory,
  GlobalWAFRule,
  GlobalWAFRuleCategory,
  GlobalWAFPolicyHistory,
} from '../types/waf';
import { HelpTip } from './common/HelpTip';
import { CategoryIcon } from './waf-settings';

export function WAFSettings() {
  const { t } = useTranslation('waf');
  const [mainTab, setMainTab] = useState<'global' | 'hosts'>('global');
  const [selectedHost, setSelectedHost] = useState<WAFHostConfig | null>(null);

  const hostsQuery = useQuery({
    queryKey: ['waf-hosts'],
    queryFn: fetchWAFHostConfigs,
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('settings.title')}</h1>
          <p className="text-sm text-gray-500 dark:text-slate-400 mt-1">
            {mainTab === 'hosts' ? t('hostList.subtitle') : t('global.subtitle')}
          </p>
        </div>
      </div>

      {/* Main Tabs */}
      <div className="border-b dark:border-slate-700">
        <div className="flex gap-4">
          <button
            onClick={() => setMainTab('global')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors flex items-center gap-2 ${mainTab === 'global'
              ? 'border-blue-600 dark:border-blue-500 text-blue-600 dark:text-blue-500'
              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'
            }`}
          >
            {t('global.tabs.global')}
            <HelpTip contentKey="help.global.description" ns="waf" />
          </button>
          <button
            onClick={() => setMainTab('hosts')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${mainTab === 'hosts'
              ? 'border-blue-600 dark:border-blue-500 text-blue-600 dark:text-blue-500'
              : 'border-transparent text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-200'
            }`}
          >
            {t('global.tabs.perHost')}
          </button>
        </div>
      </div>

      {mainTab === 'global' ? (
        <GlobalWAFSettings />
      ) : (
        <>
          {/* Host Cards */}
          {hostsQuery.isLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : hostsQuery.error ? (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-600 dark:text-red-400">
              {t('hostList.loadError')}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {(hostsQuery.data?.hosts || []).map((host) => (
                <WAFHostCard
                  key={host.proxy_host_id}
                  host={host}
                  onManage={() => setSelectedHost(host)}
                />
              ))}
              {(!hostsQuery.data?.hosts || hostsQuery.data.hosts.length === 0) && (
                <div className="col-span-full bg-gray-50 dark:bg-slate-800/50 rounded-lg p-8 text-center text-gray-500 dark:text-slate-400">
                  {t('hostList.noHosts')}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* WAF Rules Modal */}
      {selectedHost && (
        <WAFRulesModal
          host={selectedHost}
          onClose={() => setSelectedHost(null)}
        />
      )}
    </div>
  );
}

function WAFHostCard({
  host,
  onManage,
}: {
  host: WAFHostConfig;
  onManage: () => void;
}) {
  const { t } = useTranslation('waf');
  const getStatusColor = () => {
    if (!host.waf_enabled) return 'bg-gray-100 dark:bg-slate-800 border-gray-200 dark:border-slate-700';
    if (host.waf_mode === 'blocking') return 'bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-900/30';
    return 'bg-yellow-50 dark:bg-yellow-900/10 border-yellow-200 dark:border-yellow-900/30';
  };

  const getStatusBadge = () => {
    if (!host.waf_enabled) {
      return (
        <span className="px-2 py-0.5 text-xs rounded-full bg-gray-200 text-gray-600 flex items-center gap-1">
          {t('hostList.status.inactive')}
          <HelpTip contentKey="help.hostList.status" ns="waf" />
        </span>
      );
    }
    if (host.waf_mode === 'blocking') {
      return <span className="px-2 py-0.5 text-xs rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400">{t('hostList.status.blocking')}</span>;
    }
    return <span className="px-2 py-0.5 text-xs rounded-full bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400">{t('hostList.status.detection')}</span>;
  };

  return (
    <div className={`rounded-lg border p-4 ${getStatusColor()}`}>
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center ${host.waf_enabled
              ? host.waf_mode === 'blocking'
                ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400'
                : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400'
              : 'bg-gray-200 dark:bg-slate-700 text-gray-400 dark:text-slate-500'
              }`}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <div>
            <h3 className="font-semibold text-gray-900 dark:text-white">{host.proxy_host_name || 'Unnamed Host'}</h3>
            {getStatusBadge()}
          </div>
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-slate-700/50 flex items-center justify-between">
        <div className="text-sm">
          {host.exclusion_count > 0 ? (
            <span className="text-orange-600 dark:text-orange-400 font-medium">
              {t('hostList.rulesDisabled', { count: host.exclusion_count })}
            </span>
          ) : (
            <span className="text-gray-500 dark:text-slate-500">{t('hostList.allRulesEnabled')}</span>
          )}
        </div>
        <button
          onClick={onManage}
          disabled={!host.waf_enabled}
          className={`px-3 py-1.5 text-sm rounded-lg transition-colors ${host.waf_enabled
            ? 'bg-blue-600 text-white hover:bg-blue-700 dark:hover:bg-blue-500'
            : 'bg-gray-200 dark:bg-slate-700 text-gray-400 dark:text-slate-500 cursor-not-allowed'
            }`}
        >
          {t('hostList.managePolicy')}
        </button>
      </div>
    </div>
  );
}

function WAFRulesModal({
  host,
  onClose,
}: {
  host: WAFHostConfig;
  onClose: () => void;
}) {
  const { t } = useTranslation('waf');
  const [activeTab, setActiveTab] = useState<'rules' | 'history'>('rules');
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showDisabledOnly, setShowDisabledOnly] = useState(false);
  const queryClient = useQueryClient();

  const rulesQuery = useQuery({
    queryKey: ['waf-rules', host.proxy_host_id],
    queryFn: () => fetchWAFRules(host.proxy_host_id),
  });

  const historyQuery = useQuery({
    queryKey: ['waf-policy-history', host.proxy_host_id],
    queryFn: () => fetchWAFPolicyHistory(host.proxy_host_id, 100),
    enabled: activeTab === 'history',
  });

  const disableMutation = useMutation({
    mutationFn: ({ ruleId, category, description, reason }: {
      ruleId: number;
      category?: string;
      description?: string;
      reason?: string;
    }) =>
      disableWAFRule(host.proxy_host_id, ruleId, {
        rule_id: ruleId,
        rule_category: category,
        rule_description: description,
        reason: reason,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['waf-rules', host.proxy_host_id] });
      queryClient.invalidateQueries({ queryKey: ['waf-hosts'] });
      queryClient.invalidateQueries({ queryKey: ['waf-policy-history', host.proxy_host_id] });
    },
  });

  const enableMutation = useMutation({
    mutationFn: (ruleId: number) => enableWAFRule(host.proxy_host_id, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['waf-rules', host.proxy_host_id] });
      queryClient.invalidateQueries({ queryKey: ['waf-hosts'] });
      queryClient.invalidateQueries({ queryKey: ['waf-policy-history', host.proxy_host_id] });
    },
  });

  // State for disable reason modal
  const [disableModalRule, setDisableModalRule] = useState<{
    rule: WAFRule;
    categoryName: string;
  } | null>(null);
  const [disableReason, setDisableReason] = useState('');

  const handleToggleRule = (rule: WAFRule, categoryName: string) => {
    if (rule.enabled) {
      // Show modal to input reason
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

  // Filter rules
  const filteredData = useMemo(() => {
    if (!rulesQuery.data) return { categories: [], totalRules: 0, disabledRules: 0 };

    const query = searchQuery.toLowerCase();
    let totalRules = 0;
    let disabledRules = 0;

    // Handle null categories (when no rules exist)
    if (!rulesQuery.data.categories) {
      return { categories: [], totalRules: 0, disabledRules: 0 };
    }

    const categories = rulesQuery.data.categories
      .map((cat) => {
        let rules = cat.rules || [];

        // Filter by search
        if (query) {
          rules = rules.filter(
            (r) =>
              r.id.toString().includes(query) ||
              r.description?.toLowerCase().includes(query)
          );
        }

        // Filter by disabled only
        if (showDisabledOnly) {
          rules = rules.filter((r) => !r.enabled);
        }

        totalRules += rules.length;
        disabledRules += rules.filter((r) => !r.enabled).length;

        return { ...cat, rules };
      })
      .filter((cat) => {
        if (activeCategory === 'all') return cat.rules && cat.rules.length > 0;
        return cat.id === activeCategory;
      });

    return { categories, totalRules, disabledRules };
  }, [rulesQuery.data, searchQuery, showDisabledOnly, activeCategory]);

  // Bulk actions
  const handleBulkDisable = (categoryId: string) => {
    const category = rulesQuery.data?.categories.find((c) => c.id === categoryId);
    if (!category?.rules) return;

    category.rules
      .filter((r) => r.enabled)
      .forEach((rule) => {
        disableMutation.mutate({
          ruleId: rule.id,
          category: category.name,
          description: rule.description,
        });
      });
  };

  const handleBulkEnable = (categoryId: string) => {
    const category = rulesQuery.data?.categories.find((c) => c.id === categoryId);
    if (!category?.rules) return;

    category.rules
      .filter((r) => !r.enabled)
      .forEach((rule) => {
        enableMutation.mutate(rule.id);
      });
  };

  const isPending = disableMutation.isPending || enableMutation.isPending;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />

      {/* Modal */}
      <div className="absolute inset-4 md:inset-8 lg:inset-12 bg-white dark:bg-slate-800 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex-shrink-0 px-6 py-4 border-b dark:border-slate-700 bg-gray-50 dark:bg-slate-900 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              {t('policyManager.title', { name: host.proxy_host_name })}
            </h2>
            <p className="text-sm text-gray-500 dark:text-slate-400 mt-0.5">
              {t('policyManager.subtitle', { total: rulesQuery.data?.total_rules || 0, disabled: host.exclusion_count })}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-200 dark:hover:bg-slate-700 rounded-lg transition-colors text-slate-500 dark:text-slate-400"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="flex-shrink-0 px-6 border-b dark:border-slate-700 bg-white dark:bg-slate-800">
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

        {/* Toolbar - only show for rules tab */}
        {activeTab === 'rules' && (
          <div className="flex-shrink-0 px-6 py-3 border-b dark:border-slate-700 bg-white dark:bg-slate-800 flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <svg
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-slate-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
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

            {/* Filter Toggle */}
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={showDisabledOnly}
                onChange={(e) => setShowDisabledOnly(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
              />
              <span className="text-sm text-gray-600 dark:text-slate-300">
                {t('policyManager.showDisabledOnly')}
                <HelpTip contentKey="help.policyManager.showDisabledOnly" ns="waf" />
              </span>
            </label>

            {/* Results count */}
            <div className="text-sm text-gray-500 dark:text-slate-400">
              {t('policyManager.showingCount', { count: filteredData.totalRules })}
              {filteredData.disabledRules > 0 && (
                <span className="text-orange-600 dark:text-orange-400 ml-1">
                  {t('policyManager.disabledCount', { count: filteredData.disabledRules })}
                </span>
              )}
            </div>
          </div>
        )}

        {/* Content Area */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {activeTab === 'rules' ? (
            <>
              {/* Category Sidebar */}
              <div className="w-full md:w-48 h-auto md:h-full flex-shrink-0 border-b md:border-b-0 md:border-r border-slate-200 dark:border-slate-700 bg-gray-50 dark:bg-slate-900 overflow-x-auto md:overflow-y-auto flex md:block scrollbar-hide">
                <div className="flex md:block p-2 gap-2 min-w-max">
                  <button
                    onClick={() => setActiveCategory('all')}
                    className={`w-auto md:w-full whitespace-nowrap px-3 py-2 text-left rounded-lg text-sm transition-colors ${activeCategory === 'all'
                      ? 'bg-blue-600 text-white'
                      : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-700 dark:text-slate-300'
                      }`}
                  >
                    {t('policyManager.allCategories')}
                  </button>
                  {rulesQuery.data?.categories?.map((cat) => {
                    const disabledCount = cat.rules?.filter((r) => !r.enabled).length || 0;
                    return (
                      <button
                        key={cat.id}
                        onClick={() => setActiveCategory(cat.id)}
                        className={`w-auto md:w-full whitespace-nowrap px-3 py-2 text-left rounded-lg text-sm transition-colors mt-0 md:mt-1 ${activeCategory === cat.id
                          ? 'bg-blue-600 text-white'
                          : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-700 dark:text-slate-300'
                          }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="truncate">{cat.name}</span>
                          {disabledCount > 0 && (
                            <span
                              className={`ml-1 px-1.5 py-0.5 text-xs rounded ${activeCategory === cat.id
                                ? 'bg-blue-500 text-white'
                                : 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400'
                                }`}
                            >
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
                  <div className="p-6 text-center text-red-600">
                    {t('policyManager.loadError')}
                  </div>
                ) : filteredData.categories.length === 0 ? (
                  <div className="p-6 text-center text-gray-500 dark:text-slate-400">
                    {searchQuery ? t('policyManager.noResults') : t('policyManager.empty')}
                  </div>
                ) : (
                  <div className="divide-y">
                    {filteredData.categories.map((category) => (
                      <CategoryRulesSection
                        key={category.id}
                        category={category}
                        onToggleRule={(rule) => handleToggleRule(rule, category.name)}
                        onBulkDisable={() => handleBulkDisable(category.id)}
                        onBulkEnable={() => handleBulkEnable(category.id)}
                        isPending={isPending}
                        showCategoryHeader={activeCategory === 'all'}
                      />
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            /* History Tab */
            <div className="flex-1 flex flex-col overflow-hidden">
              <PolicyHistoryPanel
                history={historyQuery.data?.history || []}
                isLoading={historyQuery.isLoading}
                error={historyQuery.error}
              />
            </div>
          )}
        </div>
      </div>

      {/* Disable Reason Modal */}
      {disableModalRule && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => setDisableModalRule(null)}
          />
          <div className="relative bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
            <div className="px-6 py-4 border-b dark:border-slate-700 bg-gray-50 dark:bg-slate-900">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{t('disableModal.title')}</h3>
            </div>
            <div className="p-6">
              <div className="mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-0.5 rounded text-xs font-mono bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400">
                    {disableModalRule.rule.id}
                  </span>
                  <span className="text-sm font-medium text-gray-700 dark:text-slate-300">
                    {disableModalRule.categoryName}
                  </span>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400">
                  {disableModalRule.rule.description || t('policyManager.noDescription')}
                </p>
              </div>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                  {t('disableModal.reasonLabel')} <span className="text-gray-400 dark:text-slate-500">({t('common.optional', { defaultValue: '선택' })})</span>
                </label>
                <textarea
                  value={disableReason}
                  onChange={(e) => setDisableReason(e.target.value)}
                  placeholder={t('disableModal.reasonPlaceholder')}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-white dark:placeholder-slate-400 resize-none"
                  rows={3}
                  autoFocus
                />
              </div>

              <div className="flex gap-3 justify-end">
                <button
                  onClick={() => setDisableModalRule(null)}
                  className="px-4 py-2 text-sm text-gray-700 dark:text-slate-300 bg-gray-100 dark:bg-slate-700 rounded-lg hover:bg-gray-200 dark:hover:bg-slate-600 transition-colors"
                >
                  {t('disableModal.cancel')}
                </button>
                <button
                  onClick={handleConfirmDisable}
                  disabled={disableMutation.isPending}
                  className="px-4 py-2 text-sm text-white bg-orange-600 dark:bg-orange-500 rounded-lg hover:bg-orange-700 dark:hover:bg-orange-600 transition-colors disabled:opacity-50"
                >
                  {disableMutation.isPending ? t('disableModal.processing') : t('disableModal.confirm')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function CategoryRulesSection({
  category,
  onToggleRule,
  onBulkDisable,
  onBulkEnable,
  isPending,
  showCategoryHeader,
}: {
  category: WAFRuleCategory;
  onToggleRule: (rule: WAFRule) => void;
  onBulkDisable: () => void;
  onBulkEnable: () => void;
  isPending: boolean;
  showCategoryHeader: boolean;
}) {
  const { t } = useTranslation('waf');
  const [isExpanded, setIsExpanded] = useState(true);
  const enabledCount = category.rules?.filter((r) => r.enabled).length || 0;
  const disabledCount = (category.rules?.length || 0) - enabledCount;

  return (
    <div>
      {showCategoryHeader && (
        <div className="sticky top-0 bg-white dark:bg-slate-800 border-b dark:border-slate-700 px-4 py-3 flex items-center justify-between z-10">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-3"
          >
            <CategoryIcon name={category.name} />
            <div className="text-left">
              <div className="font-semibold text-gray-900 dark:text-white">{category.name}</div>
              <div className="text-xs text-gray-500 dark:text-slate-400">
                {category.description} | {t('policyManager.ruleCount', { count: category.rules?.length || 0 })}
                {disabledCount > 0 && (
                  <span className="text-orange-600 dark:text-orange-400 ml-1">{t('policyManager.disabledCount', { count: disabledCount })}</span>
                )}
              </div>
            </div>
            <svg
              className={`w-4 h-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          <div className="flex gap-2">
            {disabledCount > 0 && (
              <button
                onClick={onBulkEnable}
                disabled={isPending}
                className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded hover:bg-green-200 transition-colors disabled:opacity-50"
              >
                {t('policyManager.bulkEnable')}
              </button>
            )}
            {enabledCount > 0 && (
              <button
                onClick={onBulkDisable}
                disabled={isPending}
                className="px-2 py-1 text-xs bg-red-100 text-red-700 rounded hover:bg-red-200 transition-colors disabled:opacity-50"
              >
                {t('policyManager.bulkDisable')}
              </button>
            )}
          </div>
        </div>
      )}

      {(!showCategoryHeader || isExpanded) && (
        <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
          {category.rules?.map((rule) => (
            <RuleRow
              key={rule.id}
              rule={rule}
              onToggle={() => onToggleRule(rule)}
              isPending={isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function RuleRow({
  rule,
  onToggle,
  isPending,
}: {
  rule: WAFRule;
  onToggle: () => void;
  isPending: boolean;
}) {
  const { t, i18n } = useTranslation('waf');
  const [showDetails, setShowDetails] = useState(false);
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString(i18n.language, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  // Check if rule has details to show
  const hasDetails = rule.exclusion || rule.global_exclusion;

  return (
    <div className={`${rule.globally_disabled ? 'bg-purple-50 dark:bg-purple-900/10' : !rule.enabled ? 'bg-orange-50 dark:bg-orange-900/10' : 'bg-white dark:bg-slate-800'}`}>
      <div
        className={`px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors cursor-pointer`}
        onClick={() => hasDetails && setShowDetails(!showDetails)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={`px-2 py-0.5 rounded text-xs font-mono ${rule.globally_disabled
              ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'
              : rule.enabled
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                : 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'
              }`}
          >
            {rule.id}
          </span>
          <span className="text-sm text-gray-700 dark:text-slate-300 truncate" title={rule.description}>
            {rule.description || t('policyManager.noDescription')}
          </span>
          {rule.globally_disabled && (
            <span className="px-1.5 py-0.5 text-xs rounded bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {t('global.badge')}
            </span>
          )}
          {rule.severity && !rule.globally_disabled && (
            <span
              className={`px-1.5 py-0.5 text-xs rounded ${rule.severity === 'CRITICAL'
                ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                : rule.severity === 'ERROR'
                  ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400'
                  : rule.severity === 'WARNING'
                    ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                    : 'bg-gray-100 text-gray-600 dark:bg-slate-700 dark:text-slate-400'
                }`}
            >
              {rule.severity}
            </span>
          )}
          {hasDetails && (
            <svg
              className={`w-4 h-4 text-gray-400 transition-transform ${showDetails ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
        {rule.globally_disabled ? (
          <span className="text-xs text-purple-600 dark:text-purple-400 italic px-3">
            {t('global.badge')}
          </span>
        ) : (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
            disabled={isPending}
            className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${rule.enabled ? 'bg-green-500' : 'bg-gray-300'
              } ${isPending ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            <span
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${rule.enabled ? 'translate-x-5' : 'translate-x-0'
                }`}
            />
          </button>
        )}
      </div>

      {/* Exclusion Details Panel - Host-specific */}
      {showDetails && rule.exclusion && !rule.globally_disabled && (
        <div className="px-4 pb-3 ml-8 mr-4">
          <div className="bg-orange-100 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-900/40 rounded-lg p-3 text-sm">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span className="font-semibold text-orange-800 dark:text-orange-300">{t('policyManager.exclusionInfo')}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-orange-900 dark:text-orange-200">
              <div>
                <span className="text-orange-600 dark:text-orange-400 text-xs">{t('policyManager.disabledAt')}</span>
                <p className="font-medium">{formatDate(rule.exclusion.created_at)}</p>
              </div>
              {rule.exclusion.reason && (
                <div>
                  <span className="text-orange-600 dark:text-orange-400 text-xs">{t('policyManager.reason')}</span>
                  <p className="font-medium">{rule.exclusion.reason}</p>
                </div>
              )}
              {rule.exclusion.disabled_by && (
                <div>
                  <span className="text-orange-600 dark:text-orange-400 text-xs">{t('policyManager.disabledBy')}</span>
                  <p className="font-medium">{rule.exclusion.disabled_by}</p>
                </div>
              )}
              {rule.exclusion.rule_category && (
                <div>
                  <span className="text-orange-600 dark:text-orange-400 text-xs">{t('policyManager.category')}</span>
                  <p className="font-medium">{rule.exclusion.rule_category}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Exclusion Details Panel - Global */}
      {showDetails && rule.global_exclusion && (
        <div className="px-4 pb-3 ml-8 mr-4">
          <div className="bg-purple-100 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-900/40 rounded-lg p-3 text-sm">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
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

function PolicyHistoryPanel({
  history,
  isLoading,
  error,
}: {
  history: WAFPolicyHistory[];
  isLoading: boolean;
  error: Error | null;
}) {
  const [historySearch, setHistorySearch] = useState('');

  const filteredHistory = useMemo(() => {
    if (!historySearch.trim()) return history;
    const query = historySearch.trim().toLowerCase();
    return history.filter(
      (item) =>
        item.rule_id.toString().includes(query) ||
        item.rule_category?.toLowerCase().includes(query) ||
        item.rule_description?.toLowerCase().includes(query)
    );
  }, [history, historySearch]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 text-center text-red-600 dark:text-red-400">
        변경 이력을 불러오는데 실패했습니다
      </div>
    );
  }

  return (
    <>
      {/* Search Bar */}
      <div className="flex-shrink-0 px-6 py-3 border-b dark:border-slate-700 bg-white dark:bg-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex-1 max-w-xs">
            <div className="relative">
              <svg
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-slate-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                placeholder="규칙 ID 또는 카테고리로 검색..."
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-white dark:placeholder-slate-400"
              />
            </div>
          </div>
          <div className="text-sm text-gray-500 dark:text-slate-400">
            {filteredHistory.length}개 이력
            {historySearch && history.length !== filteredHistory.length && (
              <span className="text-gray-400 dark:text-slate-500 ml-1">
                (전체 {history.length}개)
              </span>
            )}
          </div>
        </div>
      </div>

      {/* History List */}
      <div className="flex-1 overflow-y-auto">
        <PolicyHistoryList history={filteredHistory} />
      </div>
    </>
  );
}

function PolicyHistoryList({ history }: { history: WAFPolicyHistory[] }) {
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  if (history.length === 0) {
    return (
      <div className="p-12 text-center text-gray-500 dark:text-slate-400">
        <svg className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p className="text-lg font-medium">변경 이력이 없습니다</p>
        <p className="text-sm mt-1">정책을 변경하면 이력이 기록됩니다</p>
      </div>
    );
  }

  return (
    <div className="divide-y">
      {history.map((item) => (
        <div key={item.id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-slate-700/50">
          <div className="flex items-start gap-4">
            {/* Action Icon */}
            <div
              className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${item.action === 'disabled'
                ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400'
                : 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400'
                }`}
            >
              {item.action === 'disabled' ? (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`px-2 py-0.5 text-xs font-medium rounded ${item.action === 'disabled'
                    ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400'
                    : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                    }`}
                >
                  {item.action === 'disabled' ? '비활성화' : '활성화'}
                </span>
                <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white">
                  #{item.rule_id}
                </span>
                {item.rule_category && (
                  <span className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 rounded">
                    {item.rule_category}
                  </span>
                )}
              </div>

              {item.rule_description && (
                <p className="text-sm text-gray-700 dark:text-slate-300 mb-1">{item.rule_description}</p>
              )}

              {item.reason && (
                <p className="text-sm text-gray-500 dark:text-slate-400">
                  <span className="font-medium">사유:</span> {item.reason}
                </p>
              )}

              <div className="flex items-center gap-4 mt-2 text-xs text-gray-400 dark:text-slate-500">
                <span>{formatDate(item.created_at)}</span>
                {item.changed_by && (
                  <span>by {item.changed_by}</span>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Global WAF Settings Component
// ============================================================================

function GlobalWAFSettings() {
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

  // State for disable reason modal
  const [disableModalRule, setDisableModalRule] = useState<{
    rule: GlobalWAFRule;
    categoryName: string;
  } | null>(null);
  const [disableReason, setDisableReason] = useState('');

  const handleToggleRule = (rule: GlobalWAFRule, categoryName: string) => {
    if (!rule.globally_disabled) {
      // Show modal to input reason
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

  // Filter rules
  const filteredData = useMemo(() => {
    if (!rulesQuery.data) return { categories: [], totalRules: 0, disabledRules: 0 };

    const query = searchQuery.toLowerCase();
    let totalRules = 0;
    let disabledRules = 0;

    // Handle null categories (when no rules exist)
    if (!rulesQuery.data.categories) {
      return { categories: [], totalRules: 0, disabledRules: 0 };
    }

    const categories = rulesQuery.data.categories
      .map((cat) => {
        let rules = cat.rules || [];

        // Filter by search
        if (query) {
          rules = rules.filter(
            (r) =>
              r.id.toString().includes(query) ||
              r.description?.toLowerCase().includes(query)
          );
        }

        // Filter by disabled only
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
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
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
            {/* Search */}
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <svg
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-slate-500"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
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

            {/* Filter Toggle */}
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={showDisabledOnly}
                onChange={(e) => setShowDisabledOnly(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded focus:ring-blue-500"
              />
              <span className="text-sm text-gray-600 dark:text-slate-300">
                {t('global.showDisabledOnly')}
              </span>
            </label>

            {/* Results count */}
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
                  className={`w-auto md:w-full whitespace-nowrap px-3 py-2 text-left rounded-lg text-sm transition-colors ${activeCategory === 'all'
                    ? 'bg-blue-600 text-white'
                    : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-700 dark:text-slate-300'
                  }`}
                >
                  {t('policyManager.allCategories')}
                </button>
                {rulesQuery.data?.categories?.map((cat) => {
                  const disabledCount = cat.rules?.filter((r) => r.globally_disabled).length || 0;
                  return (
                    <button
                      key={cat.id}
                      onClick={() => setActiveCategory(cat.id)}
                      className={`w-auto md:w-full whitespace-nowrap px-3 py-2 text-left rounded-lg text-sm transition-colors mt-0 md:mt-1 ${activeCategory === cat.id
                        ? 'bg-blue-600 text-white'
                        : 'hover:bg-gray-200 dark:hover:bg-slate-800 text-gray-700 dark:text-slate-300'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="truncate">{cat.name}</span>
                        {disabledCount > 0 && (
                          <span
                            className={`ml-1 px-1.5 py-0.5 text-xs rounded ${activeCategory === cat.id
                              ? 'bg-blue-500 text-white'
                              : 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400'
                            }`}
                          >
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
                <div className="p-6 text-center text-red-600">
                  {t('policyManager.loadError')}
                </div>
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
        /* History Tab */
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
          <div
            className="absolute inset-0 bg-black/50"
            onClick={() => setDisableModalRule(null)}
          />
          <div className="relative bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
            <div className="px-6 py-4 border-b dark:border-slate-700 bg-purple-50 dark:bg-purple-900/20">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{t('global.disableModal.title')}</h3>
              <p className="text-sm text-purple-600 dark:text-purple-400 mt-1">{t('global.disableModal.warning')}</p>
            </div>
            <div className="p-6">
              <div className="mb-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-0.5 rounded text-xs font-mono bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400">
                    {disableModalRule.rule.id}
                  </span>
                  <span className="text-sm font-medium text-gray-700 dark:text-slate-300">
                    {disableModalRule.categoryName}
                  </span>
                </div>
                <p className="text-sm text-gray-600 dark:text-slate-400">
                  {disableModalRule.rule.description || t('policyManager.noDescription')}
                </p>
              </div>

              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 dark:text-slate-300 mb-1">
                  {t('disableModal.reasonLabel')} <span className="text-gray-400 dark:text-slate-500">({t('common.optional', { defaultValue: '선택' })})</span>
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
                <button
                  onClick={() => setDisableModalRule(null)}
                  className="px-4 py-2 text-sm text-gray-700 dark:text-slate-300 bg-gray-100 dark:bg-slate-700 rounded-lg hover:bg-gray-200 dark:hover:bg-slate-600 transition-colors"
                >
                  {t('disableModal.cancel')}
                </button>
                <button
                  onClick={handleConfirmDisable}
                  disabled={disableMutation.isPending}
                  className="px-4 py-2 text-sm text-white bg-purple-600 dark:bg-purple-500 rounded-lg hover:bg-purple-700 dark:hover:bg-purple-600 transition-colors disabled:opacity-50"
                >
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
  category,
  onToggleRule,
  isPending,
  showCategoryHeader,
  formatDate,
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
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-3"
          >
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
            <svg
              className={`w-4 h-4 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
      )}

      {(!showCategoryHeader || isExpanded) && (
        <div className="divide-y divide-gray-100 dark:divide-slate-700/50">
          {category.rules?.map((rule) => (
            <GlobalRuleRow
              key={rule.id}
              rule={rule}
              onToggle={() => onToggleRule(rule)}
              isPending={isPending}
              formatDate={formatDate}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function GlobalRuleRow({
  rule,
  onToggle,
  isPending,
  formatDate,
}: {
  rule: GlobalWAFRule;
  onToggle: () => void;
  isPending: boolean;
  formatDate: (dateStr: string) => string;
}) {
  const { t } = useTranslation('waf');
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div className={`${rule.globally_disabled ? 'bg-purple-50 dark:bg-purple-900/10' : 'bg-white dark:bg-slate-800'}`}>
      <div
        className={`px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors cursor-pointer`}
        onClick={() => rule.global_exclusion && setShowDetails(!showDetails)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={`px-2 py-0.5 rounded text-xs font-mono ${!rule.globally_disabled ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400'
            }`}
          >
            {rule.id}
          </span>
          <span className="text-sm text-gray-700 dark:text-slate-300 truncate" title={rule.description}>
            {rule.description || t('policyManager.noDescription')}
          </span>
          {rule.globally_disabled && (
            <span className="px-1.5 py-0.5 text-xs rounded bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {t('global.badge')}
            </span>
          )}
          {rule.global_exclusion && (
            <svg
              className={`w-4 h-4 text-gray-400 transition-transform ${showDetails ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          disabled={isPending}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 ${!rule.globally_disabled ? 'bg-green-500' : 'bg-gray-300'
          } ${isPending ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          <span
            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${!rule.globally_disabled ? 'translate-x-5' : 'translate-x-0'
            }`}
          />
        </button>
      </div>

      {/* Exclusion Details Panel */}
      {showDetails && rule.global_exclusion && (
        <div className="px-4 pb-3 ml-8 mr-4">
          <div className="bg-purple-100 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-900/40 rounded-lg p-3 text-sm">
            <div className="flex items-center gap-2 mb-2">
              <svg className="w-4 h-4 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
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

function GlobalPolicyHistoryPanel({
  history,
  isLoading,
  error,
}: {
  history: GlobalWAFPolicyHistory[];
  isLoading: boolean;
  error: Error | null;
}) {
  const { t } = useTranslation('waf');
  const [historySearch, setHistorySearch] = useState('');

  const filteredHistory = useMemo(() => {
    if (!historySearch.trim()) return history;
    const query = historySearch.trim().toLowerCase();
    return history.filter(
      (item) =>
        item.rule_id.toString().includes(query) ||
        item.rule_category?.toLowerCase().includes(query) ||
        item.rule_description?.toLowerCase().includes(query)
    );
  }, [history, historySearch]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 text-center text-red-600 dark:text-red-400">
        {t('global.history.loadError')}
      </div>
    );
  }

  return (
    <>
      {/* Search Bar */}
      <div className="flex-shrink-0 px-6 py-3 border-b dark:border-slate-700 bg-white dark:bg-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex-1 max-w-xs">
            <div className="relative">
              <svg
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-slate-500"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                placeholder={t('global.history.searchPlaceholder')}
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-slate-700 text-gray-900 dark:text-white dark:placeholder-slate-400"
              />
            </div>
          </div>
          <div className="text-sm text-gray-500 dark:text-slate-400">
            {t('global.history.count', { count: filteredHistory.length })}
            {historySearch && history.length !== filteredHistory.length && (
              <span className="text-gray-400 dark:text-slate-500 ml-1">
                ({t('global.history.total', { count: history.length })})
              </span>
            )}
          </div>
        </div>
      </div>

      {/* History List */}
      <div className="flex-1 overflow-y-auto">
        <GlobalPolicyHistoryList history={filteredHistory} />
      </div>
    </>
  );
}

function GlobalPolicyHistoryList({ history }: { history: GlobalWAFPolicyHistory[] }) {
  const { t, i18n } = useTranslation('waf');
  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString(i18n.language, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  if (history.length === 0) {
    return (
      <div className="p-12 text-center text-gray-500 dark:text-slate-400">
        <svg className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p className="text-lg font-medium">{t('global.history.empty')}</p>
        <p className="text-sm mt-1">{t('global.history.emptyDescription')}</p>
      </div>
    );
  }

  return (
    <div className="divide-y">
      {history.map((item) => (
        <div key={item.id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-slate-700/50">
          <div className="flex items-start gap-4">
            {/* Action Icon */}
            <div
              className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${item.action === 'disabled'
                ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400'
                : 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400'
              }`}
            >
              {item.action === 'disabled' ? (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              )}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span
                  className={`px-2 py-0.5 text-xs font-medium rounded ${item.action === 'disabled'
                    ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400'
                    : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                  }`}
                >
                  {item.action === 'disabled' ? t('global.history.disabled') : t('global.history.enabled')}
                </span>
                <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white">
                  #{item.rule_id}
                </span>
                {item.rule_category && (
                  <span className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-slate-300 rounded">
                    {item.rule_category}
                  </span>
                )}
                <span className="px-1.5 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded flex items-center gap-1">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  {t('global.badge')}
                </span>
              </div>

              {item.rule_description && (
                <p className="text-sm text-gray-700 dark:text-slate-300 mb-1">{item.rule_description}</p>
              )}

              {item.reason && (
                <p className="text-sm text-gray-500 dark:text-slate-400">
                  <span className="font-medium">{t('global.history.reason')}:</span> {item.reason}
                </p>
              )}

              <div className="flex items-center gap-4 mt-2 text-xs text-gray-400 dark:text-slate-500">
                <span>{formatDate(item.created_at)}</span>
                {item.changed_by && (
                  <span>by {item.changed_by}</span>
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

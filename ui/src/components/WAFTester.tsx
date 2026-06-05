import { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { fetchAttackPatterns, testAttack, testAllAttacks, WAFTestResult, AttackPattern } from '../api/waf-test';
import { fetchProxyHosts } from '../api/proxy-hosts';
import type { ProxyHost } from '../types/proxy-host';
import { useTranslation } from 'react-i18next';
import { HelpTip } from './common/HelpTip';

const categoryColors: Record<string, string> = {
  'SQL Injection': 'bg-red-100 text-red-800',
  'XSS': 'bg-orange-100 text-orange-800',
  'Path Traversal': 'bg-yellow-100 text-yellow-800',
  'Command Injection': 'bg-purple-100 text-purple-800',
  'Scanner Detection': 'bg-blue-100 text-blue-800',
  'RCE': 'bg-pink-100 text-pink-800',
  'Protocol Attack': 'bg-indigo-100 text-indigo-800',
};

function ResultBadge({ blocked, statusCode }: { blocked: boolean; statusCode: number }) {
  const { t } = useTranslation('waf');
  if (blocked) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300">
        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
        </svg>
        {t('tester.result.blocked', { code: statusCode })}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300">
      <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
      </svg>
      {t('tester.result.passed', { code: statusCode })}
    </span>
  );
}

interface PatternCardProps {
  pattern: AttackPattern;
  onTest: () => void;
  isLoading: boolean;
  result?: WAFTestResult;
}

function PatternCard({ pattern, onTest, isLoading, result }: PatternCardProps) {
  const { t } = useTranslation('waf');
  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-4 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between mb-2">
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${categoryColors[pattern.category] || 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'}`}>
          {pattern.category}
        </span>
        {result && <ResultBadge blocked={result.blocked} statusCode={result.status_code} />}
      </div>
      <h3 className="font-medium text-slate-900 dark:text-white mb-1">{pattern.description}</h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mb-3">{pattern.id}</p>
      <div className="flex items-center justify-between">
        <button
          onClick={onTest}
          disabled={isLoading}
          className="px-3 py-1.5 text-xs font-medium text-white bg-primary-600 dark:bg-primary-500 hover:bg-primary-700 dark:hover:bg-primary-600 rounded-lg disabled:opacity-50 transition-colors"
        >

          {isLoading ? t('tester.patterns.testing') : t('tester.patterns.test')}
        </button>
        {result && (
          <span className="text-xs text-slate-400">
            {result.response_time_ms}ms
          </span>
        )}
      </div>
    </div>
  );
}

export function WAFTester() {
  const { t } = useTranslation('waf');
  const [targetUrl, setTargetUrl] = useState('https://npg-proxy');
  const [hostHeader, setHostHeader] = useState('');
  const [selectedHostId, setSelectedHostId] = useState<string>('');
  const [results, setResults] = useState<Record<string, WAFTestResult>>({});
  const [testingId, setTestingId] = useState<string | null>(null);

  // Fetch proxy hosts for dropdown
  const proxyHostsQuery = useQuery({
    queryKey: ['proxy-hosts'],
    queryFn: () => fetchProxyHosts(1, 100),
  });

  // Filter to only show WAF-enabled hosts
  const wafEnabledHosts: ProxyHost[] = proxyHostsQuery.data?.data?.filter((h: ProxyHost) => h.waf_enabled && h.enabled) || [];
  const allHosts: ProxyHost[] = proxyHostsQuery.data?.data?.filter((h: ProxyHost) => h.enabled) || [];

  // Update host header when a proxy host is selected
  useEffect(() => {
    if (selectedHostId && proxyHostsQuery.data?.data) {
      const host = proxyHostsQuery.data.data.find((h: ProxyHost) => h.id === selectedHostId);
      if (host && host.domain_names.length > 0) {
        setHostHeader(host.domain_names[0]);
      }
    }
  }, [selectedHostId, proxyHostsQuery.data]);

  const patternsQuery = useQuery({
    queryKey: ['attack-patterns'],
    queryFn: fetchAttackPatterns,
  });

  const testMutation = useMutation({
    mutationFn: ({ attackType }: { attackType: string }) =>
      testAttack(targetUrl, attackType, hostHeader || undefined),
    onSuccess: (result) => {
      setResults((prev) => ({ ...prev, [result.attack_type]: result }));
      setTestingId(null);
    },
    onError: () => {
      setTestingId(null);
    },
  });

  const testAllMutation = useMutation({
    mutationFn: () => testAllAttacks(targetUrl, hostHeader || undefined),
    onSuccess: (resultList) => {
      const newResults: Record<string, WAFTestResult> = {};
      resultList.forEach((r) => {
        newResults[r.attack_type] = r;
      });
      setResults(newResults);
    },
  });

  const handleTest = (attackType: string) => {
    setTestingId(attackType);
    testMutation.mutate({ attackType });
  };

  const handleTestAll = () => {
    setResults({});
    testAllMutation.mutate();
  };

  // Calculate stats
  const resultList = Object.values(results);
  const totalTests = resultList.length;
  const blockedCount = resultList.filter((r) => r.blocked).length;
  const passedCount = totalTests - blockedCount;

  return (
    <div className="space-y-6">
      {/* Target URL */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-6">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">{t('tester.title')}</h2>
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
          {t('tester.description')}
          <span className="text-orange-600 dark:text-orange-400 font-medium"> {t('tester.warning')}</span>
        </p>

        {/* Proxy Host Selection */}
        <div className="mb-4">
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
            {t('tester.selectHost')}
            <HelpTip contentKey="help.tester.selectHost" ns="waf" />
          </label>
          <select
            value={selectedHostId}
            onChange={(e) => setSelectedHostId(e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="">{t('tester.selectHostPlaceholder')}</option>
            {wafEnabledHosts.length > 0 && (
              <optgroup label={t('tester.wafEnabledGroup')}>
                {wafEnabledHosts.map((host) => (
                  <option key={host.id} value={host.id}>
                    {host.domain_names[0]} {host.waf_mode === 'blocking' ? t('tester.options.blocking') : t('tester.options.detection')}
                  </option>
                ))}
              </optgroup>
            )}
            {allHosts.filter((h: ProxyHost) => !h.waf_enabled).length > 0 && (
              <optgroup label={t('tester.wafDisabledGroup')}>
                {allHosts.filter((h: ProxyHost) => !h.waf_enabled).map((host: ProxyHost) => (
                  <option key={host.id} value={host.id}>
                    {host.domain_names[0]} {t('tester.options.noWaf')}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
          {wafEnabledHosts.length === 0 && allHosts.length > 0 && (
            <p className="text-xs text-orange-600 dark:text-orange-400 mt-1">
              {t('tester.noWafHosts')}
            </p>
          )}
        </div>

        <div className="flex gap-4 flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
              {t('tester.targetUrl')}
              <HelpTip contentKey="help.tester.targetUrl" ns="waf" />
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://npg-proxy"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('tester.targetUrlHelp')}</p>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
              {t('tester.hostHeader')}
              <HelpTip contentKey="help.tester.hostHeader" ns="waf" />
            </label>
            <input
              type="text"
              value={hostHeader}
              onChange={(e) => {
                setHostHeader(e.target.value);
                setSelectedHostId(''); // Clear selection when manually editing
              }}
              placeholder="example.com"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('tester.hostHeaderHelp')}</p>
          </div>
          <div className="flex items-start pt-6">
            <button
              onClick={handleTestAll}
              disabled={testAllMutation.isPending || !targetUrl || !hostHeader}
              className="px-4 py-2 text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 rounded-lg disabled:opacity-50 transition-colors"
            >
              {testAllMutation.isPending ? t('tester.testingAll') : t('tester.testAll')}
            </button>
          </div>
        </div>

        {/* Selected host info */}
        {selectedHostId && proxyHostsQuery.data?.data && (
          <div className="mt-4 p-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg border border-slate-200 dark:border-slate-700">
            {(() => {
              const host = proxyHostsQuery.data.data.find((h: ProxyHost) => h.id === selectedHostId);
              if (!host) return null;
              return (
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-slate-600 dark:text-slate-300">
                    <strong>{t('tester.target')}</strong> {host.domain_names.join(', ')}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${host.waf_enabled
                    ? host.waf_mode === 'blocking'
                      ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
                      : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300'
                    : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
                    }`}>
                    {host.waf_enabled
                      ? host.waf_mode === 'blocking' ? t('tester.status.blocking') : t('tester.status.detection')
                      : t('tester.status.disabled')}
                  </span>
                  <span className="text-slate-500 dark:text-slate-400">
                    → {host.forward_scheme}://{host.forward_host}:{host.forward_port}
                  </span>
                </div>
              );
            })()}
          </div>
        )}
      </div>

      {/* Results Summary */}
      {totalTests > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('tester.stats.total')}</p>
            <p className="text-2xl font-bold text-slate-900 dark:text-white mt-1">{totalTests}</p>
          </div>
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-green-500 dark:text-green-400 uppercase">{t('tester.stats.blocked')}</p>
            <p className="text-2xl font-bold text-green-600 dark:text-green-400 mt-1">{blockedCount}</p>
          </div>
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-4">
            <p className="text-xs font-medium text-red-500 dark:text-red-400 uppercase">{t('tester.stats.passed')}</p>
            <p className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">{passedCount}</p>
          </div>
        </div>
      )}

      {/* Attack Patterns Grid */}
      <div>
        <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">{t('tester.patterns.title')}</h3>
        {patternsQuery.isLoading ? (
          <div className="text-center py-8 text-slate-500">{t('tester.patterns.loading')}</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {patternsQuery.data?.map((pattern) => (
              <PatternCard
                key={pattern.id}
                pattern={pattern}
                onTest={() => handleTest(pattern.id)}
                isLoading={testingId === pattern.id || testAllMutation.isPending}
                result={results[pattern.id]}
              />
            ))}
          </div>
        )}
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex gap-3">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
          <div>
            <h4 className="text-sm font-medium text-blue-900 dark:text-blue-300">{t('tester.modeInfo.title')}</h4>
            <p className="text-sm text-blue-700 dark:text-blue-400 mt-1">
              <strong>{t('tester.modeInfo.blocking')}</strong><br />
              <strong>{t('tester.modeInfo.detection')}</strong><br />
              {t('tester.modeInfo.configure')}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

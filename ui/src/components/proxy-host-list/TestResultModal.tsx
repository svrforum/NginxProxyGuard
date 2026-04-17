import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeKey } from '../../hooks/useEscapeKey';
import type { ProxyHost, ProxyHostTestResult } from '../../types/proxy-host';
import { SummaryTab } from './TestResultSummary';
import { SSLTab, HTTPTab, CacheTab } from './TestResultDetails';
import { SecurityTab, HeadersTab } from './TestResultLogs';

interface TestResultModalProps {
  host: ProxyHost;
  result: ProxyHostTestResult | null;
  isLoading: boolean;
  error: string | null;
  onClose: () => void;
  onRetest: () => void;
}

export function TestResultModal({
  host,
  result,
  isLoading,
  error,
  onClose,
  onRetest,
}: TestResultModalProps) {
  const { t } = useTranslation('proxyHost');
  const [activeTab, setActiveTab] = useState<'summary' | 'ssl' | 'http' | 'cache' | 'security' | 'headers'>('summary');

  useEscapeKey(onClose);

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('test.title')}</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">{host.domain_names[0]}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onRetest}
              disabled={isLoading}
              className="px-3 py-1.5 text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg flex items-center gap-1.5"
            >
              <svg className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {t('test.retest')}
            </button>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="flex-1 flex items-center justify-center py-20">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600 mx-auto mb-4" />
              <p className="text-slate-600 dark:text-slate-400">{t('test.testing')}</p>
            </div>
          </div>
        )}

        {/* Error State */}
        {error && !isLoading && (
          <div className="flex-1 flex items-center justify-center py-20">
            <div className="text-center">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-red-600 font-medium mb-2">{t('test.failed')}</p>
              <p className="text-slate-500 dark:text-slate-400 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Result Content */}
        {result && !isLoading && (
          <>
            {/* Tabs */}
            <div className="px-6 border-b border-slate-200 dark:border-slate-700">
              <nav className="flex gap-1 -mb-px">
                {[
                  { id: 'summary', label: t('test.tabs.summary') },
                  { id: 'ssl', label: t('test.tabs.ssl') },
                  { id: 'http', label: t('test.tabs.http') },
                  { id: 'cache', label: t('test.tabs.cache') },
                  { id: 'security', label: t('test.tabs.security') },
                  { id: 'headers', label: t('test.tabs.headers') },
                ].map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${activeTab === tab.id
                      ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                      : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                      }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-auto p-6">
              {activeTab === 'summary' && <SummaryTab result={result} host={host} />}
              {activeTab === 'ssl' && <SSLTab result={result} />}
              {activeTab === 'http' && <HTTPTab result={result} host={host} />}
              {activeTab === 'cache' && <CacheTab result={result} host={host} />}
              {activeTab === 'security' && <SecurityTab result={result} />}
              {activeTab === 'headers' && <HeadersTab result={result} />}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

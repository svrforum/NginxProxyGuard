import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  fetchWAFHostConfigs,
} from '../api/waf';
import type {
  WAFHostConfig,
} from '../types/waf';
import { HelpTip } from './common/HelpTip';
import { GlobalWAFSettings } from './waf-settings/GlobalWAFSettings';
import { WAFRulesModal } from './waf-settings/WAFRulesModal';

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
            <h3 className="font-semibold text-gray-900 dark:text-white">{host.proxy_host_name || t('policyManager.unnamedHost')}</h3>
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


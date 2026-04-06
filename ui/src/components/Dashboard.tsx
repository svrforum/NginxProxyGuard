import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { getDashboard, runSelfCheck, getContainerStats, getGeoIPStats } from '../api/settings';
import WorldMapVisualization from './WorldMapVisualization';
import HostResourcesSection from './dashboard/HostResourcesSection';
import ContainerStatsSection from './dashboard/ContainerStatsSection';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

export default function Dashboard() {
  const { t } = useTranslation('dashboard');
  const { data: dashboard, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard'],
    queryFn: getDashboard,
    refetchInterval: 60000,
  });

  const { data: selfCheck, refetch: runCheck } = useQuery({
    queryKey: ['selfCheck'],
    queryFn: runSelfCheck,
    enabled: false,
  });

  const { data: containerStats } = useQuery({
    queryKey: ['containerStats'],
    queryFn: getContainerStats,
    refetchInterval: 60000,
  });

  const { data: geoIPStats, isLoading: geoIPLoading } = useQuery({
    queryKey: ['geoIPStats'],
    queryFn: () => getGeoIPStats(24),
    refetchInterval: 120000,
  });

  const countryCodePattern = /^[A-Z]{2}$/i;
  const filteredCountries = useMemo(() => {
    if (!geoIPStats?.data) return [];
    return geoIPStats.data
      .filter((country) => country.country_code && country.country_code !== '--' && countryCodePattern.test(country.country_code))
      .slice(0, 10);
  }, [geoIPStats?.data]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
        <p className="text-red-600 dark:text-red-400">Failed to load dashboard</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('title')}</h1>
        <div className="flex gap-2">
          <button
            onClick={() => runCheck()}
            className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:text-gray-200 dark:hover:bg-slate-600 rounded-lg"
          >
            {t('actions.selfCheck')}
          </button>
          <button
            onClick={() => refetch()}
            className="px-3 py-1.5 text-sm bg-blue-600 text-white hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-700 rounded-lg"
          >
            {t('actions.refresh')}
          </button>
        </div>
      </div>

      {/* Self Check Result */}
      {selfCheck && (
        <div className={`p-4 rounded-lg ${selfCheck.status === 'healthy'
          ? 'bg-green-50 border border-green-200 dark:bg-green-900/20 dark:border-green-800'
          : 'bg-yellow-50 border border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800'}`}>
          <div className="flex items-center gap-2">
            <span className={`w-3 h-3 rounded-full ${selfCheck.status === 'healthy' ? 'bg-green-500' : 'bg-yellow-500'}`}></span>
            <span className="font-medium dark:text-gray-200">{t('status.systemStatus', { status: selfCheck.status === 'healthy' ? t('status.healthy') : t('status.unhealthy') })}</span>
          </div>
        </div>
      )}

      {/* Host System Resources */}
      {dashboard?.system_health && (
        <HostResourcesSection systemHealth={dashboard.system_health} />
      )}

      {/* Container Resources - Collapsible */}
      {containerStats && containerStats.containers && containerStats.containers.length > 0 && (
        <ContainerStatsSection containerStats={containerStats} />
      )}

      {/* Blocked Stats - BunkerWeb Style */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gradient-to-br from-red-600 to-red-700 rounded-lg shadow p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-red-100 text-sm font-medium">{t('stats.blockedRequests')}</p>
              <p className="text-4xl font-bold mt-2">{formatNumber(dashboard?.blocked_requests_24h || 0)}</p>
              <p className="text-red-200 text-xs mt-1">{t('stats.last24h')}</p>
            </div>
            <div className="bg-red-500/30 p-3 rounded-full">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
          </div>
        </div>

        <div className="bg-gradient-to-br from-amber-500 to-amber-600 rounded-lg shadow p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-amber-100 text-sm font-medium">{t('stats.blockedIps')}</p>
              <p className="text-4xl font-bold mt-2">{dashboard?.blocked_unique_ips_24h || 0}</p>
              <p className="text-amber-200 text-xs mt-1">{t('stats.last24h')}</p>
            </div>
            <div className="bg-amber-400/30 p-3 rounded-full">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Traffic Stats (24h) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg shadow p-4 text-white">
          <p className="text-blue-100 text-sm">{t('stats.requests')} (24h)</p>
          <p className="text-3xl font-bold mt-1">{formatNumber(dashboard?.total_requests_24h || 0)}</p>
        </div>

        <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-lg shadow p-4 text-white">
          <p className="text-green-100 text-sm">{t('stats.bandwidth')} (24h)</p>
          <p className="text-3xl font-bold mt-1">{formatBytes(dashboard?.total_bandwidth_24h || 0)}</p>
        </div>

        <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-lg shadow p-4 text-white">
          <p className="text-purple-100 text-sm">{t('stats.avgResponseTime')}</p>
          <p className="text-3xl font-bold mt-1">{(dashboard?.avg_response_time_24h || 0).toFixed(1)}ms</p>
        </div>

        <div className="bg-gradient-to-br from-orange-500 to-orange-600 rounded-lg shadow p-4 text-white">
          <p className="text-orange-100 text-sm">{t('stats.errorRate')} (24h)</p>
          <p className="text-3xl font-bold mt-1">{(dashboard?.error_rate_24h || 0).toFixed(2)}%</p>
        </div>
      </div>

      {/* Security Stats */}
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
        <div className="p-4 border-b dark:border-slate-700">
          <h2 className="text-lg font-semibold dark:text-white">{t('security.title')}</h2>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 divide-x dark:divide-slate-700">
          <div className="p-4 text-center">
            <p className="text-3xl font-bold text-red-600 dark:text-red-500">{formatNumber(dashboard?.waf_blocked_24h || 0)}</p>
            <p className="text-gray-500 dark:text-gray-400 text-sm">{t('security.wafBlocked')}</p>
          </div>
          <div className="p-4 text-center">
            <p className="text-3xl font-bold text-yellow-600 dark:text-yellow-500">{formatNumber(dashboard?.rate_limited_24h || 0)}</p>
            <p className="text-gray-500 dark:text-gray-400 text-sm">{t('security.rateLimited')}</p>
          </div>
          <div className="p-4 text-center">
            <p className="text-3xl font-bold text-purple-600 dark:text-purple-500">{formatNumber(dashboard?.bot_blocked_24h || 0)}</p>
            <p className="text-gray-500 dark:text-gray-400 text-sm">{t('security.botsBlocked')}</p>
          </div>
          <div className="p-4 text-center">
            <p className="text-3xl font-bold text-gray-600 dark:text-gray-300">{dashboard?.banned_ips || 0}</p>
            <p className="text-gray-500 dark:text-gray-400 text-sm">{t('security.bannedIps')}</p>
          </div>
        </div>
      </div>

      {/* Hosts Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
          <div className="p-4 border-b dark:border-slate-700">
            <h2 className="text-lg font-semibold dark:text-white">{t('hosts.title')}</h2>
          </div>
          <div className="p-4 space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-600 dark:text-gray-400">{t('hosts.proxyHosts')}</span>
              <span className="font-semibold dark:text-gray-200">{dashboard?.active_proxy_hosts || 0} / {dashboard?.total_proxy_hosts || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600 dark:text-gray-400">{t('hosts.redirectHosts')}</span>
              <span className="font-semibold dark:text-gray-200">{dashboard?.total_redirect_hosts || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-600 dark:text-gray-400">{t('hosts.certificates')}</span>
              <span className="font-semibold dark:text-gray-200">{dashboard?.total_certificates || 0}</span>
            </div>
            {(dashboard?.expiring_certificates || 0) > 0 && (
              <div className="flex justify-between items-center text-yellow-600 dark:text-yellow-500">
                <span>{t('hosts.expiringSoon')}</span>
                <span className="font-semibold">{dashboard?.expiring_certificates}</span>
              </div>
            )}
          </div>
        </div>

        {/* Top Hosts */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
          <div className="p-4 border-b dark:border-slate-700">
            <h2 className="text-lg font-semibold dark:text-white">{t('topLists.hostsTitle')}</h2>
          </div>
          <div className="p-4">
            {dashboard?.top_hosts && dashboard.top_hosts.length > 0 ? (
              <div className="space-y-2">
                {dashboard.top_hosts.slice(0, 5).map((host, i) => (
                  <div key={i} className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-300 truncate">{host.domain}</span>
                    <span className="font-mono text-sm dark:text-gray-400">{formatNumber(host.requests)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 dark:text-gray-400 text-sm">{t('topLists.noData')}</p>
            )}
          </div>
        </div>

        {/* Top IPs */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
          <div className="p-4 border-b dark:border-slate-700">
            <h2 className="text-lg font-semibold dark:text-white">{t('topLists.ipsTitle')}</h2>
          </div>
          <div className="p-4">
            {dashboard?.top_ips && dashboard.top_ips.length > 0 ? (
              <div className="space-y-2">
                {dashboard.top_ips.slice(0, 5).map((ip, i) => (
                  <div key={i} className="flex justify-between items-center">
                    <span className="text-gray-600 dark:text-gray-300 font-mono text-sm">{ip.ip}</span>
                    <span className="font-mono text-sm dark:text-gray-400">{formatNumber(ip.count)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 dark:text-gray-400 text-sm">{t('topLists.noData')}</p>
            )}
          </div>
        </div>

        {/* Top User Agents */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
          <div className="p-4 border-b dark:border-slate-700">
            <h2 className="text-lg font-semibold dark:text-white">{t('topLists.userAgentsTitle')}</h2>
          </div>
          <div className="p-4">
            {dashboard?.top_user_agents && dashboard.top_user_agents.length > 0 ? (
              <div className="space-y-2">
                {dashboard.top_user_agents.slice(0, 5).map((ua, i) => (
                  <div key={i} className="flex flex-col gap-0.5">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-600 dark:text-gray-300 text-xs truncate max-w-[180px]" title={ua.user_agent}>
                        {ua.user_agent.length > 30 ? ua.user_agent.substring(0, 30) + '...' : ua.user_agent}
                      </span>
                      <span className="font-mono text-sm dark:text-gray-400">{formatNumber(ua.count)}</span>
                    </div>
                    <span className={`text-xs px-1.5 py-0.5 rounded w-fit ${ua.category === 'search_engine' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                      ua.category === 'ai_bot' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' :
                        ua.category === 'bad_bot' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                          ua.category === 'monitoring' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' :
                            ua.category === 'cli_tool' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                              ua.category === 'browser' ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400' :
                                ua.category === 'mobile' ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400' :
                                  'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                      }`}>
                      {ua.category}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 dark:text-gray-400 text-sm">{t('topLists.noData')}</p>
            )}
          </div>
        </div>
      </div>

      {/* GeoIP Globe Visualization */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Globe */}
        <div className="lg:col-span-2 bg-slate-900 rounded-lg shadow overflow-hidden">
          <div className="p-4 border-b border-slate-700 flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">{t('geo.title')}</h2>
            <span className="text-xs text-slate-400">{t('geo.subtitle')}</span>
          </div>
          <div className="h-[380px]">
            <WorldMapVisualization
              data={geoIPStats?.data || []}
              isLoading={geoIPLoading}
            />
          </div>
        </div>

        {/* Top Countries List */}
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
          <div className="p-4 border-b dark:border-slate-700 flex items-center justify-between">
            <h2 className="text-lg font-semibold dark:text-white">{t('geo.topCountries')}</h2>
            {geoIPStats && (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Total: {formatNumber(geoIPStats.total_count)} requests
              </p>
            )}
          </div>
          <div className="p-4">
            {filteredCountries.length > 0 ? (
              <div className="space-y-2">
                {filteredCountries.map((country, i) => (
                    <div key={i} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">
                          {country.country_code
                            .toUpperCase()
                            .split('')
                            .map(char => String.fromCodePoint(127397 + char.charCodeAt(0)))
                            .join('')}
                        </span>
                        <span className="text-gray-700 dark:text-gray-300">{country.country}</span>
                      </div>
                      <div className="text-right">
                        <span className="font-mono text-sm dark:text-gray-400">{formatNumber(country.count)}</span>
                        <span className="text-gray-400 text-xs ml-2">({country.percentage.toFixed(1)}%)</span>
                      </div>
                    </div>
                  ))}
              </div>
            ) : dashboard?.top_countries && dashboard.top_countries.length > 0 ? (
              <div className="space-y-2">
                {dashboard.top_countries.slice(0, 10).map((country, i) => (
                  <div key={i} className="flex items-center justify-between">
                    <span className="text-gray-700 dark:text-gray-300">{country.country}</span>
                    <span className="font-mono text-sm dark:text-gray-400">{formatNumber(country.count)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 dark:text-gray-400 text-sm text-center py-4">{t('topLists.noData')}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

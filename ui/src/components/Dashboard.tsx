import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { getDashboard, runSelfCheck, getContainerStats, getGeoIPStats, getSystemHealthHistory } from '../api/settings';
import WorldMapVisualization from './WorldMapVisualization';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

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
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const { data: selfCheck, refetch: runCheck } = useQuery({
    queryKey: ['selfCheck'],
    queryFn: runSelfCheck,
    enabled: false,
  });

  const { data: containerStats } = useQuery({
    queryKey: ['containerStats'],
    queryFn: getContainerStats,
    refetchInterval: 15000, // Refresh every 15 seconds
  });

  const { data: geoIPStats, isLoading: geoIPLoading } = useQuery({
    queryKey: ['geoIPStats'],
    queryFn: () => getGeoIPStats(24),
    refetchInterval: 60000, // Refresh every minute
  });

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
            {geoIPStats?.data && geoIPStats.data.length > 0 ? (
              <div className="space-y-2">
                {geoIPStats.data
                  .filter((country) => country.country_code && country.country_code !== '--' && /^[A-Z]{2}$/i.test(country.country_code))
                  .slice(0, 10)
                  .map((country, i) => (
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

// Time range options for charts
const TIME_RANGES = [
  { value: 1, label: '1h', points: 120 },
  { value: 4, label: '4h', points: 240 },
  { value: 12, label: '12h', points: 360 },
  { value: 24, label: '24h', points: 480 },
] as const;

// Host System Resources Section with expandable charts
function HostResourcesSection({ systemHealth }: {
  systemHealth: {
    cpu_usage: number;
    memory_usage: number;
    memory_total: number;
    memory_used: number;
    disk_usage: number;
    disk_total: number;
    disk_used: number;
    disk_path: string;
    uptime_seconds: number;
    hostname: string;
    os: string;
    platform: string;
    kernel_version: string;
    network_in: number;
    network_out: number;
  }
}) {
  const { t } = useTranslation('dashboard');
  const [showCharts, setShowCharts] = useState(false);
  const [timeRange, setTimeRange] = useState<typeof TIME_RANGES[number]>(TIME_RANGES[0]);

  // Fetch history data when charts are shown
  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ['systemHealthHistory', timeRange.value],
    queryFn: () => getSystemHealthHistory(timeRange.value, timeRange.points),
    refetchInterval: 30000,
    enabled: showCharts,
  });

  // Format uptime
  const formatUptime = (seconds: number): string => {
    if (!seconds || seconds === 0) return '-';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h ${mins}m`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
  };

  // Get color based on usage percentage
  const getUsageColor = (percent: number): string => {
    if (percent >= 90) return 'bg-red-500';
    if (percent >= 70) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const getUsageTextColor = (percent: number): string => {
    if (percent >= 90) return 'text-red-600 dark:text-red-400';
    if (percent >= 70) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-green-600 dark:text-green-400';
  };

  // Format chart data with network I/O rate calculation
  const chartData = historyData?.data?.map((item, index, arr) => {
    // Calculate network rate (bytes/sec) from cumulative values
    let networkInRate = 0;
    let networkOutRate = 0;

    if (index > 0) {
      const prevItem = arr[index - 1];
      const timeDiff = (new Date(item.recorded_at).getTime() - new Date(prevItem.recorded_at).getTime()) / 1000;
      if (timeDiff > 0) {
        // Handle counter reset (reboot)
        const inDiff = item.network_in >= prevItem.network_in ? item.network_in - prevItem.network_in : item.network_in;
        const outDiff = item.network_out >= prevItem.network_out ? item.network_out - prevItem.network_out : item.network_out;
        networkInRate = inDiff / timeDiff; // bytes/sec
        networkOutRate = outDiff / timeDiff; // bytes/sec
      }
    }

    // Format time based on range
    const date = new Date(item.recorded_at);
    const timeFormat = timeRange.value > 4
      ? { hour: '2-digit', minute: '2-digit' } as const
      : { hour: '2-digit', minute: '2-digit' } as const;

    return {
      time: date.toLocaleTimeString('ko-KR', timeFormat),
      fullTime: date.toLocaleString('ko-KR'),
      cpu: item.cpu_usage,
      memory: item.memory_usage,
      disk: item.disk_usage,
      networkIn: networkInRate / 1024, // KB/s
      networkOut: networkOutRate / 1024, // KB/s
    };
  }).slice(1) || []; // Remove first item (no rate data)

  // Custom tooltip style
  const tooltipStyle = {
    backgroundColor: 'rgba(15, 23, 42, 0.95)',
    border: 'none',
    borderRadius: '8px',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
      {/* Header */}
      <div className="p-4 border-b dark:border-slate-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-100 dark:bg-cyan-900/30 text-cyan-600 dark:text-cyan-400 flex items-center justify-center">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
              </svg>
            </div>
            <div>
              <h2 className="text-lg font-semibold dark:text-white">{t('hostResources.title')}</h2>
              <div className="text-sm text-gray-500 dark:text-gray-400 flex flex-wrap items-center gap-x-3 gap-y-1">
                {systemHealth.hostname && <span>{systemHealth.hostname}</span>}
                {systemHealth.platform && <span className="capitalize">{systemHealth.platform}</span>}
                {systemHealth.uptime_seconds > 0 && (
                  <span className="flex items-center gap-1">
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {t('hostResources.uptime')}: {formatUptime(systemHealth.uptime_seconds)}
                  </span>
                )}
              </div>
            </div>
          </div>
          {/* Chart Toggle Button */}
          <button
            onClick={() => setShowCharts(!showCharts)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 ${
              showCharts
                ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                : 'bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-slate-600'
            }`}
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            {showCharts ? t('hostResources.hideCharts', 'Hide') : t('hostResources.showCharts', 'Charts')}
          </button>
        </div>
      </div>

      {/* Current Usage - Always Visible */}
      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* CPU */}
        <div className="p-3 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
          <div className="flex justify-between items-center mb-2">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
              </svg>
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">CPU</span>
            </div>
            <span className={`text-lg font-bold ${getUsageTextColor(systemHealth.cpu_usage)}`}>
              {systemHealth.cpu_usage?.toFixed(1) || '0'}%
            </span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-slate-600 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full transition-all duration-500 ${getUsageColor(systemHealth.cpu_usage)}`}
              style={{ width: `${Math.min(systemHealth.cpu_usage || 0, 100)}%` }}
            ></div>
          </div>
        </div>

        {/* Memory */}
        <div className="p-3 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
          <div className="flex justify-between items-center mb-2">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('hostResources.memory')}</span>
            </div>
            <span className={`text-lg font-bold ${getUsageTextColor(systemHealth.memory_usage)}`}>
              {systemHealth.memory_usage?.toFixed(1) || '0'}%
            </span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-slate-600 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full transition-all duration-500 ${getUsageColor(systemHealth.memory_usage)}`}
              style={{ width: `${Math.min(systemHealth.memory_usage || 0, 100)}%` }}
            ></div>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {formatBytes(systemHealth.memory_used || 0)} / {formatBytes(systemHealth.memory_total || 0)}
          </div>
        </div>

        {/* Disk */}
        <div className="p-3 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
          <div className="flex justify-between items-center mb-2">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
              </svg>
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('hostResources.disk')}</span>
            </div>
            <span className={`text-lg font-bold ${getUsageTextColor(systemHealth.disk_usage)}`}>
              {systemHealth.disk_usage?.toFixed(1) || '0'}%
            </span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-slate-600 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full transition-all duration-500 ${getUsageColor(systemHealth.disk_usage)}`}
              style={{ width: `${Math.min(systemHealth.disk_usage || 0, 100)}%` }}
            ></div>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {formatBytes(systemHealth.disk_used || 0)} / {formatBytes(systemHealth.disk_total || 0)}
          </div>
        </div>

        {/* Network I/O */}
        <div className="p-3 bg-gray-50 dark:bg-slate-700/50 rounded-lg">
          <div className="flex items-center gap-2 mb-2">
            <svg className="w-4 h-4 text-teal-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
            </svg>
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('hostResources.network')}</span>
          </div>
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                <svg className="w-3 h-3 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                </svg>
                {t('hostResources.networkIn')}
              </span>
              <span className="text-sm font-semibold text-green-600 dark:text-green-400">
                {formatBytes(systemHealth.network_in || 0)}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1">
                <svg className="w-3 h-3 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
                </svg>
                {t('hostResources.networkOut')}
              </span>
              <span className="text-sm font-semibold text-blue-600 dark:text-blue-400">
                {formatBytes(systemHealth.network_out || 0)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section - Toggled */}
      {showCharts && (
        <div className="border-t dark:border-slate-700">
          {/* Time Range Selector */}
          <div className="p-4 flex items-center justify-between border-b dark:border-slate-700">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
              {t('hostResources.timeRange', 'Time Range')}
            </span>
            <div className="flex gap-1 bg-gray-100 dark:bg-slate-700 rounded-lg p-1">
              {TIME_RANGES.map((range) => (
                <button
                  key={range.value}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                    timeRange.value === range.value
                      ? 'bg-white dark:bg-slate-600 text-blue-600 dark:text-blue-400 shadow-sm'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
                  }`}
                >
                  {range.label}
                </button>
              ))}
            </div>
          </div>

          {historyLoading ? (
            <div className="p-8 flex items-center justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : chartData.length > 0 ? (
            <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* CPU Chart */}
              <div className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-slate-700/50 dark:to-slate-700/30 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center">
                    <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                    </svg>
                  </div>
                  <span className="text-sm font-semibold text-gray-700 dark:text-gray-200">CPU</span>
                </div>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" opacity={0.5} vertical={false} />
                      <XAxis dataKey="time" tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} interval="preserveStartEnd" />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} unit="%" width={35} />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        labelStyle={{ color: '#9CA3AF', fontSize: 11 }}
                        itemStyle={{ color: '#F3F4F6', fontSize: 12 }}
                        formatter={(value: number) => [`${value.toFixed(1)}%`, 'CPU']}
                      />
                      <Area type="monotone" dataKey="cpu" stroke="#3B82F6" strokeWidth={2} fill="url(#cpuGradient)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Memory Chart */}
              <div className="bg-gradient-to-br from-purple-50 to-pink-50 dark:from-slate-700/50 dark:to-slate-700/30 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-purple-500/10 flex items-center justify-center">
                    <svg className="w-4 h-4 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                    </svg>
                  </div>
                  <span className="text-sm font-semibold text-gray-700 dark:text-gray-200">{t('hostResources.memory')}</span>
                </div>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="memoryGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#A855F7" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#A855F7" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" opacity={0.5} vertical={false} />
                      <XAxis dataKey="time" tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} interval="preserveStartEnd" />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} unit="%" width={35} />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        labelStyle={{ color: '#9CA3AF', fontSize: 11 }}
                        itemStyle={{ color: '#F3F4F6', fontSize: 12 }}
                        formatter={(value: number) => [`${value.toFixed(1)}%`, t('hostResources.memory')]}
                      />
                      <Area type="monotone" dataKey="memory" stroke="#A855F7" strokeWidth={2} fill="url(#memoryGradient)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Disk Chart */}
              <div className="bg-gradient-to-br from-orange-50 to-amber-50 dark:from-slate-700/50 dark:to-slate-700/30 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-orange-500/10 flex items-center justify-center">
                    <svg className="w-4 h-4 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                    </svg>
                  </div>
                  <span className="text-sm font-semibold text-gray-700 dark:text-gray-200">{t('hostResources.disk')}</span>
                </div>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="diskGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#F97316" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#F97316" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" opacity={0.5} vertical={false} />
                      <XAxis dataKey="time" tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} interval="preserveStartEnd" />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} unit="%" width={35} />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        labelStyle={{ color: '#9CA3AF', fontSize: 11 }}
                        itemStyle={{ color: '#F3F4F6', fontSize: 12 }}
                        formatter={(value: number) => [`${value.toFixed(1)}%`, t('hostResources.disk')]}
                      />
                      <Area type="monotone" dataKey="disk" stroke="#F97316" strokeWidth={2} fill="url(#diskGradient)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Network Chart */}
              <div className="bg-gradient-to-br from-teal-50 to-cyan-50 dark:from-slate-700/50 dark:to-slate-700/30 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-teal-500/10 flex items-center justify-center">
                    <svg className="w-4 h-4 text-teal-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
                    </svg>
                  </div>
                  <span className="text-sm font-semibold text-gray-700 dark:text-gray-200">{t('hostResources.network')}</span>
                  <div className="flex items-center gap-3 ml-auto text-xs">
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      {t('hostResources.networkIn')}
                    </span>
                    <span className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                      {t('hostResources.networkOut')}
                    </span>
                  </div>
                </div>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="networkInGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#10B981" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#10B981" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="networkOutGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" opacity={0.5} vertical={false} />
                      <XAxis dataKey="time" tick={{ fontSize: 9 }} stroke="#9CA3AF" axisLine={false} tickLine={false} interval="preserveStartEnd" />
                      <YAxis
                        tick={{ fontSize: 9 }}
                        stroke="#9CA3AF"
                        axisLine={false}
                        tickLine={false}
                        width={45}
                        tickFormatter={(value) => {
                          if (value >= 1024) return `${(value / 1024).toFixed(0)}M`;
                          return `${value.toFixed(0)}K`;
                        }}
                      />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        labelStyle={{ color: '#9CA3AF', fontSize: 11 }}
                        itemStyle={{ fontSize: 12 }}
                        formatter={(value: number, name: string) => {
                          const formatted = value >= 1024 ? `${(value / 1024).toFixed(2)} MB/s` : `${value.toFixed(2)} KB/s`;
                          return [formatted, name === 'networkIn' ? t('hostResources.networkIn') : t('hostResources.networkOut')];
                        }}
                      />
                      <Area type="monotone" dataKey="networkIn" stroke="#10B981" strokeWidth={2} fill="url(#networkInGradient)" />
                      <Area type="monotone" dataKey="networkOut" stroke="#3B82F6" strokeWidth={2} fill="url(#networkOutGradient)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-gray-500 dark:text-gray-400">
              {t('hostResources.noData', 'No history data available yet. Data is collected every 30 seconds.')}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Container Stats Section with toggle
function ContainerStatsSection({ containerStats }: {
  containerStats: {
    containers: Array<{
      container_id: string;
      container_name: string;
      cpu_percent: number;
      memory_usage: number;
      memory_limit: number;
      memory_percent: number;
      net_i: number;
      net_o: number;
      block_i: number;
      block_o: number;
      status: string;
    }>;
    volumes?: Array<{
      name: string;
      driver: string;
      size: number;
      size_human: string;
    }>;
    total_cpu_percent: number;
    total_memory_usage: number;
    total_memory_limit: number;
    total_volume_size?: number;
    container_count: number;
    healthy_count: number;
  }
}) {
  const { t } = useTranslation('dashboard');
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full p-4 flex justify-between items-center hover:bg-gray-50 dark:hover:bg-slate-700 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
            </svg>
          </div>
          <div className="text-left">
            <h2 className="text-lg font-semibold dark:text-white">{t('containers.title')}</h2>
            <div className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-3 flex-wrap">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                {t('containers.running', { healthy: containerStats.healthy_count, total: containerStats.container_count })}
              </span>
              <span>{t('containers.cpu')}: {containerStats.total_cpu_percent.toFixed(1)}%</span>
              <span>{t('containers.memory')}: {formatBytes(containerStats.total_memory_usage)}</span>
              {containerStats.total_volume_size !== undefined && containerStats.total_volume_size > 0 && (
                <span>{t('containers.storage', 'Storage')}: {formatBytes(containerStats.total_volume_size)}</span>
              )}
            </div>
          </div>
        </div>
        <svg
          className={`w-5 h-5 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isExpanded && (
        <>
          <div className="divide-y dark:divide-slate-700 border-t dark:border-slate-700">
            {containerStats.containers.map((container) => (
              <div key={container.container_id} className="p-4">
                <div className="flex justify-between items-center mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${container.status === 'running' ? 'bg-green-500' : 'bg-red-500'
                      }`}></span>
                    <span className="font-medium dark:text-gray-200">{container.container_name}</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded ${container.status === 'running' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                    }`}>
                    {container.status}
                  </span>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">{t('containers.cpu')}</div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-200 dark:bg-slate-700 rounded-full h-2">
                        <div
                          className="bg-blue-500 h-2 rounded-full"
                          style={{ width: `${Math.min(container.cpu_percent, 100)}%` }}
                        ></div>
                      </div>
                      <span className="font-mono text-xs w-12 text-right dark:text-gray-300">{container.cpu_percent.toFixed(1)}%</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">{t('containers.memory')}</div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-200 dark:bg-slate-700 rounded-full h-2">
                        <div
                          className="bg-purple-500 h-2 rounded-full"
                          style={{ width: `${Math.min(container.memory_percent, 100)}%` }}
                        ></div>
                      </div>
                      <span className="font-mono text-xs w-12 text-right dark:text-gray-300">{container.memory_percent.toFixed(1)}%</span>
                    </div>
                    <div className="text-xs text-gray-400 mt-0.5">
                      {formatBytes(container.memory_usage)} / {formatBytes(container.memory_limit)}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">{t('containers.storage', 'Storage')}</div>
                    <div className="text-xs font-mono dark:text-gray-300">
                      {(() => {
                        // Map container name to volume name
                        const volumeMap: Record<string, string> = {
                          'npg-db': 'npg_postgres_data',
                          'npg-proxy': 'npg_nginx_data',
                          'npg-api': 'npg_api_data',
                          'npg-ui': 'npg_ui_data',
                          'npg-valkey': 'npg_valkey_data',
                        };
                        const volumeName = volumeMap[container.container_name];
                        const volume = containerStats.volumes?.find(v => v.name === volumeName);
                        return volume ? (volume.size_human || formatBytes(volume.size)) : '-';
                      })()}
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">{t('containers.networkIo')}</div>
                    <div className="text-xs font-mono">
                      <span className="text-green-600 dark:text-green-500">↓ {formatBytes(container.net_i)}</span>
                      {' / '}
                      <span className="text-blue-600 dark:text-blue-500">↑ {formatBytes(container.net_o)}</span>
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-500 dark:text-gray-400 mb-1">{t('containers.blockIo')}</div>
                    <div className="text-xs font-mono">
                      <span className="text-green-600 dark:text-green-500">↓ {formatBytes(container.block_i)}</span>
                      {' / '}
                      <span className="text-blue-600 dark:text-blue-500">↑ {formatBytes(container.block_o)}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="p-3 bg-gray-50 dark:bg-slate-700/50 border-t dark:border-slate-700 text-xs text-gray-500 dark:text-gray-400 flex justify-between flex-wrap gap-2">
            <span>{t('containers.totalCpu')} {containerStats.total_cpu_percent.toFixed(1)}%</span>
            <span>{t('containers.totalMemory')} {formatBytes(containerStats.total_memory_usage)}</span>
            {containerStats.total_volume_size !== undefined && containerStats.total_volume_size > 0 && (
              <span>{t('containers.totalStorage', 'Storage')}: {formatBytes(containerStats.total_volume_size)}</span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

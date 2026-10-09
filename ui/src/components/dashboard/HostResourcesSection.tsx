import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { getSystemHealthHistory } from '../../api/settings';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import type { StorageStatus } from '../../types/storage';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Time range options for charts
const TIME_RANGES = [
  { value: 1, label: '1h', points: 120 },
  { value: 4, label: '4h', points: 240 },
  { value: 12, label: '12h', points: 360 },
  { value: 24, label: '24h', points: 480 },
] as const;

const tooltipStyle = {
  backgroundColor: 'rgba(15, 23, 42, 0.95)',
  border: 'none',
  borderRadius: '8px',
  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
};

function getUsageColor(percent: number): string {
  if (percent >= 90) return 'bg-red-500';
  if (percent >= 70) return 'bg-yellow-500';
  return 'bg-green-500';
}

function getUsageTextColor(percent: number): string {
  if (percent >= 90) return 'text-red-600 dark:text-red-400';
  if (percent >= 70) return 'text-yellow-600 dark:text-yellow-400';
  return 'text-green-600 dark:text-green-400';
}

// The disk bar follows the server's alert lines (85/90 by default), so its
// colour turns when an alert would, not at the CPU/memory 70/90 lines.
function diskColor(percent: number, storage?: StorageStatus): string {
  const warn = storage?.thresholds.warn_percent ?? 85;
  const crit = storage?.thresholds.critical_percent ?? 90;
  if (percent >= crit) return 'bg-red-500';
  if (percent >= warn) return 'bg-amber-500';
  if (percent >= 70) return 'bg-yellow-500';
  return 'bg-green-500';
}

function diskTextColor(percent: number, storage?: StorageStatus): string {
  const warn = storage?.thresholds.warn_percent ?? 85;
  const crit = storage?.thresholds.critical_percent ?? 90;
  if (percent >= crit) return 'text-red-600 dark:text-red-400';
  if (percent >= warn) return 'text-amber-600 dark:text-amber-400';
  return getUsageTextColor(Math.min(percent, 89));
}

function formatUptime(seconds: number): string {
  if (!seconds || seconds === 0) return '-';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

export default function HostResourcesSection({ systemHealth, storage }: {
  storage?: StorageStatus;
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
  // The tile shows the primary disk (the database's, else Docker's); the
  // other filesystems are listed under it.
  const primaryDisk = storage?.filesystems.find((f) => f.roles.includes('db'))
    ?? storage?.filesystems.find((f) => f.roles.includes('docker'));
  const otherDisks = (storage?.filesystems ?? []).filter((f) => f.key !== primaryDisk?.key).slice(0, 3);
  const [timeRange, setTimeRange] = useState<typeof TIME_RANGES[number]>(TIME_RANGES[0]);

  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ['systemHealthHistory', timeRange.value],
    queryFn: () => getSystemHealthHistory(timeRange.value, timeRange.points),
    refetchInterval: 60000,
    enabled: showCharts,
  });

  const chartData = useMemo(() => {
    if (!historyData?.data) return [];
    return historyData.data.map((item, index, arr) => {
      let networkInRate = 0;
      let networkOutRate = 0;

      if (index > 0) {
        const prevItem = arr[index - 1];
        const timeDiff = (new Date(item.recorded_at).getTime() - new Date(prevItem.recorded_at).getTime()) / 1000;
        if (timeDiff > 0) {
          const inDiff = item.network_in >= prevItem.network_in ? item.network_in - prevItem.network_in : item.network_in;
          const outDiff = item.network_out >= prevItem.network_out ? item.network_out - prevItem.network_out : item.network_out;
          networkInRate = inDiff / timeDiff;
          networkOutRate = outDiff / timeDiff;
        }
      }

      const date = new Date(item.recorded_at);
      const timeFormat = { hour: '2-digit', minute: '2-digit' } as const;

      return {
        time: date.toLocaleTimeString('ko-KR', timeFormat),
        fullTime: date.toLocaleString('ko-KR'),
        cpu: item.cpu_usage,
        memory: item.memory_usage,
        disk: item.disk_usage,
        networkIn: networkInRate / 1024,
        networkOut: networkOutRate / 1024,
      };
    }).slice(1);
  }, [historyData?.data]);

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
            <span className={`text-lg font-bold ${diskTextColor(systemHealth.disk_usage, storage)}`}>
              {systemHealth.disk_usage?.toFixed(1) || '0'}%
            </span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-slate-600 rounded-full h-2.5">
            <div
              data-testid="disk-usage-bar"
              className={`h-2.5 rounded-full transition-all duration-500 ${diskColor(systemHealth.disk_usage, storage)}`}
              style={{ width: `${Math.min(systemHealth.disk_usage || 0, 100)}%` }}
            ></div>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            {formatBytes(systemHealth.disk_used || 0)} / {formatBytes(systemHealth.disk_total || 0)}
          </div>
          {systemHealth.disk_path && systemHealth.disk_path !== '/' && (
            <div className="text-[11px] text-gray-400 dark:text-gray-500 truncate" title={systemHealth.disk_path}>
              {systemHealth.disk_path}
            </div>
          )}
          {/* Other disks NPG writes to, when they are separate. At most five
              roles exist and the list is capped anyway (unbounded lists in a
              card cell broke layouts before). */}
          {otherDisks.length > 0 && (
            <ul className="mt-2 space-y-1" data-testid="disk-other-filesystems">
              {otherDisks.map((f) => (
                <li key={f.key} className="text-[11px] text-gray-500 dark:text-gray-400">
                  <div className="flex justify-between gap-2">
                    <span className="truncate" title={f.path}>
                      {f.roles.map((r) => t(`storage.roles.${r}`, { defaultValue: r })).join(', ')}
                    </span>
                    <span className={diskTextColor(f.used_percent, storage)}>{f.used_percent.toFixed(1)}%</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-slate-600 rounded-full h-1">
                    <div className={`h-1 rounded-full ${diskColor(f.used_percent, storage)}`} style={{ width: `${Math.min(f.used_percent, 100)}%` }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
          {storage && !storage.database.measured && (
            <div className="mt-1 text-[11px] text-amber-600 dark:text-amber-400" data-testid="disk-db-not-measured">
              {t('storage.dbNotMeasured', { reason: t(`storage.dbReason.${storage.database.reason || 'db_container_not_found'}`) })}
            </div>
          )}
          {storage?.stalled && storage.stalled.length > 0 && (
            <div className="mt-1 text-[11px] text-amber-600 dark:text-amber-400 break-all" data-testid="disk-stalled">
              {t('storage.stalled', {
                disks: storage.stalled.slice(0, 3).map((d) => `${t(`storage.roles.${d.role}`, { defaultValue: d.role })} (${d.path})`).join(', '),
              })}
            </div>
          )}
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
                        formatter={(value) => [`${(Number(value) || 0).toFixed(1)}%`, 'CPU']}
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
                        formatter={(value) => [`${(Number(value) || 0).toFixed(1)}%`, t('hostResources.memory')]}
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
                        formatter={(value) => [`${(Number(value) || 0).toFixed(1)}%`, t('hostResources.disk')]}
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
                  <div className="flex items-center gap-3 ml-auto text-xs text-gray-600 dark:text-gray-300">
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
                        itemStyle={{ color: '#F3F4F6', fontSize: 12 }}
                        formatter={(value, name) => {
                          const v = Number(value) || 0;
                          const formatted = v >= 1024 ? `${(v / 1024).toFixed(2)} MB/s` : `${v.toFixed(2)} KB/s`;
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

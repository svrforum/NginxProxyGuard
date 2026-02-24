import { useState } from 'react';
import { useTranslation } from 'react-i18next';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export default function ContainerStatsSection({ containerStats }: {
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

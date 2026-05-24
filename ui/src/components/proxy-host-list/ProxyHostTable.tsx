import { useTranslation } from 'react-i18next'
import type { ProxyHost } from '../../types/proxy-host'
import { ProxyHostRow } from './ProxyHostRow'
import type { TabType } from '../proxy-host/types'

interface HealthStatus {
  [hostId: string]: 'checking' | 'online' | 'offline' | 'unknown'
}

interface ProxyHostTableProps {
  hosts: ProxyHost[]
  healthStatus: HealthStatus
  onEdit: (host: ProxyHost, tab?: TabType) => void
  onDelete: (id: string) => void
  onToggle: (host: ProxyHost) => void
  onClone: (host: ProxyHost) => void
  onTestConfig: (host: ProxyHost) => void
  onCheckHealth: (hostId: string) => void
  onFavorite: (hostId: string) => void
  togglePending: boolean
}

export function ProxyHostTable({
  hosts,
  healthStatus,
  onEdit,
  onDelete,
  onToggle,
  onClone,
  onTestConfig,
  onCheckHealth,
  onFavorite,
  togglePending,
}: ProxyHostTableProps) {
  const { t } = useTranslation('proxyHost')

  return (
    <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
      <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
        <thead className="bg-slate-50 dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('list.columns.source')}
            </th>
            <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('list.columns.destination')}
            </th>
            <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('list.columns.features')}
            </th>
            <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('list.columns.status')}
            </th>
            <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('list.columns.actions')}
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
          {hosts.map((host) => (
            <ProxyHostRow
              key={host.id}
              host={host}
              healthStatus={healthStatus[host.id] ?? 'unknown'}
              togglePending={togglePending}
              onEdit={onEdit}
              onDelete={onDelete}
              onToggle={onToggle}
              onClone={onClone}
              onTestConfig={onTestConfig}
              onCheckHealth={onCheckHealth}
              onFavorite={onFavorite}
            />
          ))}
        </tbody>
      </table>
    </div>
  )
}

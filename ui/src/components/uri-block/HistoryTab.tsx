import { useTranslation } from 'react-i18next';
import type { URIMatchType } from '../../types/security';
import { DATE_TIME, formatDateTime } from '../../utils/dateTime';

function getMatchTypeColor(matchType: URIMatchType): string {
  switch (matchType) {
    case 'exact': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
    case 'prefix': return 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400'
    case 'regex': return 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400'
    default: return 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300'
  }
}

function getMatchTypeLabel(matchType: URIMatchType, t: (key: string) => string): string {
  switch (matchType) {
    case 'exact': return t('uriBlock.matchTypes.exact')
    case 'prefix': return t('uriBlock.matchTypes.prefix')
    case 'regex': return t('uriBlock.matchTypes.regex')
    default: return matchType
  }
}

function formatDate(dateStr: string, locale?: string): string {
  return formatDateTime(dateStr, DATE_TIME, locale)
}

export interface URIBlockHistoryEntry {
  id: string
  action: string
  resource_type: string
  resource_id: string
  user_email: string
  ip_address: string
  details: {
    host?: string
    name?: string
    enabled?: boolean
    action?: string
    pattern?: string
    match_type?: string
    rule_id?: string
  }
  created_at: string
}

interface HistoryTabProps {
  historyLoading: boolean;
  historyData: URIBlockHistoryEntry[] | undefined;
}

export function HistoryTab({
  historyLoading,
  historyData,
}: HistoryTabProps) {
  const { t, i18n } = useTranslation('waf');

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
      {historyLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-rose-600"></div>
        </div>
      ) : !historyData || historyData.length === 0 ? (
        <div className="text-center py-12">
          <svg className="w-16 h-16 mx-auto text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 className="mt-4 text-lg font-medium text-slate-900 dark:text-white">
            {t('uriBlock.history.empty')}
          </h3>
        </div>
      ) : (
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-800/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('uriBlock.history.time')}
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('uriBlock.history.action')}
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('uriBlock.history.host')}
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('uriBlock.history.details')}
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('uriBlock.history.user')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
            {historyData.map((entry: URIBlockHistoryEntry) => (
              <tr key={entry.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50">
                <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 whitespace-nowrap">
                  {formatDate(entry.created_at, i18n.language)}
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                    entry.details?.action === 'add_rule'
                      ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                      : entry.details?.action === 'remove_rule'
                      ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                      : 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                  }`}>
                    {entry.details?.action === 'add_rule' && t('uriBlock.history.actions.addRule')}
                    {entry.details?.action === 'remove_rule' && t('uriBlock.history.actions.removeRule')}
                    {!entry.details?.action && (entry.details?.enabled ? t('uriBlock.history.actions.enabled') : t('uriBlock.history.actions.disabled'))}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white">
                  {entry.details?.host || entry.details?.name || '-'}
                </td>
                <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                  {entry.details?.pattern && (
                    <span className="font-mono bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded text-xs">
                      {entry.details.pattern}
                    </span>
                  )}
                  {entry.details?.match_type && (
                    <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs ${getMatchTypeColor(entry.details.match_type as URIMatchType)}`}>
                      {getMatchTypeLabel(entry.details.match_type as URIMatchType, t)}
                    </span>
                  )}
                </td>
                <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
                  {entry.user_email || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

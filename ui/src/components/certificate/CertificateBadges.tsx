import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Certificate } from '../../types/certificate';

interface LinkedHost {
  domain: string;
  enabled: boolean;
}

const statusColors: Record<string, string> = {
  pending: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
  issued: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300',
  expired: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
  error: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300',
  renewing: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
};

export function StatusBadge({ status }: { status: Certificate['status'] }) {
  const { t } = useTranslation('certificates');
  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusColors[status] || statusColors.renewing}`}>
      {t(`certStatuses.${status}`)}
    </span>
  );
}

export function ProviderBadge({ provider }: { provider: Certificate['provider'] }) {
  const { t } = useTranslation('certificates');

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${provider === 'letsencrypt'
      ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300'
      : provider === 'selfsigned'
        ? 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300'
        : 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
      }`}>
      {t(`certProviders.${provider}`)}
    </span>
  );
}

export function DomainCell({ domains }: { domains: string[] }) {
  const { t } = useTranslation('certificates');
  const [expanded, setExpanded] = useState(false);

  return (
    <div>
      <div className="text-sm font-medium text-slate-900 dark:text-white">
        {domains[0]}
      </div>
      {domains.length > 1 && (
        <>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
          >
            {expanded ? t('list.collapse') : t('list.more', { count: domains.length - 1 })}
          </button>
          {expanded && (
            <div className="mt-1 space-y-0.5">
              {domains.slice(1).map((d, i) => (
                <div key={i} className="text-xs text-slate-600 dark:text-slate-400">{d}</div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export function LinkedHostsCell({ hosts }: { hosts?: LinkedHost[] }) {
  if (!hosts?.length) {
    return <span className="text-xs text-slate-400">-</span>;
  }
  return (
    <div className="space-y-0.5">
      {hosts.map((h, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${h.enabled ? 'bg-green-500' : 'bg-slate-400'}`} />
          <span className="text-xs text-slate-600 dark:text-slate-400 truncate max-w-[140px]" title={h.domain}>{h.domain}</span>
        </div>
      ))}
    </div>
  );
}

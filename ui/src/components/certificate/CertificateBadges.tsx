import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Certificate } from '../../types/certificate';

interface LinkedHost {
  domain: string;
  enabled: boolean;
  cfProxied?: boolean;
}

// Orange-cloud indicator: the linked host manages its DNS via Cloudflare DDNS
// with the proxy (orange cloud) enabled. (#216)
export function CloudflareProxyBadge() {
  const { t } = useTranslation('certificates');
  const label = t('list.cloudflareProxied');
  return (
    <span className="inline-flex items-center text-orange-500 dark:text-orange-400" title={label} aria-label={label}>
      <svg className="w-3.5 h-3.5 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
        <path d="M19.35 10.04A7.49 7.49 0 0 0 12 4C9.11 4 6.6 5.64 5.35 8.04A5.994 5.994 0 0 0 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z" />
      </svg>
    </span>
  );
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

const LINKED_HOSTS_VISIBLE = 3;

export function LinkedHostsCell({ hosts }: { hosts?: LinkedHost[] }) {
  const { t } = useTranslation('certificates');
  const [expanded, setExpanded] = useState(false);

  if (!hosts?.length) {
    return <span className="text-xs text-slate-400">-</span>;
  }

  const visible = expanded ? hosts : hosts.slice(0, LINKED_HOSTS_VISIBLE);
  const hiddenCount = hosts.length - visible.length;

  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5">
      {visible.map((h, i) => (
        <span key={i} className="inline-flex items-center gap-1">
          <span className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${h.enabled ? 'bg-green-500' : 'bg-slate-400'}`} />
          <span className="text-xs text-slate-600 dark:text-slate-400 truncate max-w-[140px]" title={h.domain}>{h.domain}</span>
          {h.cfProxied && <CloudflareProxyBadge />}
        </span>
      ))}
      {hiddenCount > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
        >
          {t('list.more', { count: hiddenCount })}
        </button>
      )}
      {expanded && hosts.length > LINKED_HOSTS_VISIBLE && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
        >
          {t('list.collapse')}
        </button>
      )}
    </span>
  );
}

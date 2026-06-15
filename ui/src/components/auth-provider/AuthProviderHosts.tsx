import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { updateProxyHost } from '../../api/proxy-hosts';
import type { ProxyHost } from '../../types/proxy-host';

interface AuthProviderHostsProps {
  providerId: string;
  /** All proxy hosts (the panel filters applied vs attachable client-side). */
  hosts: ProxyHost[];
}

/**
 * Expanded panel under an auth provider row: lists the hosts using this provider
 * (with a detach action) and a dropdown to attach a compatible unapplied host.
 * Attach/detach is a partial PUT to /proxy-hosts/:id; the server runs the
 * mutual-exclusion validation (returns 409 for challenge/custom-location/stream),
 * surfaced inline.
 */
export function AuthProviderHosts({ providerId, hosts }: AuthProviderHostsProps) {
  const { t } = useTranslation('authProvider');
  const queryClient = useQueryClient();
  const [selectedHostId, setSelectedHostId] = useState('');
  const [error, setError] = useState('');

  const applied = hosts.filter((h) => h.auth_provider_id === providerId);
  // "미적용" = no provider, and HTTP (auth_request is invalid for stream proxies).
  const attachable = hosts.filter((h) => !h.auth_provider_id && h.proxy_type !== 'stream');

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['proxy-hosts', 'for-auth-providers'] });
    queryClient.invalidateQueries({ queryKey: ['auth-providers'] });
  };

  const attachMutation = useMutation({
    mutationFn: (hostId: string) => updateProxyHost(hostId, { auth_provider_id: providerId }),
    onSuccess: () => { setSelectedHostId(''); setError(''); refresh(); },
    onError: (e: unknown) => setError(e instanceof Error ? e.message : t('hosts.attachError')),
  });

  const detachMutation = useMutation({
    mutationFn: (hostId: string) => updateProxyHost(hostId, { auth_provider_id: '' }),
    onSuccess: () => { setError(''); refresh(); },
    onError: (e: unknown) => setError(e instanceof Error ? e.message : t('hosts.detachError')),
  });

  const busy = attachMutation.isPending || detachMutation.isPending;

  return (
    <div className="space-y-4 px-4 py-4 sm:px-5 bg-slate-50/60 dark:bg-slate-900/20">
      {error && (
        <div className="flex items-start gap-2 rounded-lg bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-3 py-2 text-sm">
          <svg className="h-4 w-4 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>
          <span>{error}</span>
        </div>
      )}

      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          {t('hosts.applied')} · {applied.length}
        </p>
        {applied.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500">{t('hosts.noneApplied')}</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {applied.map((h) => (
              <span
                key={h.id}
                className="inline-flex items-center gap-2 rounded-full border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 pl-3 pr-1.5 py-1"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span className="font-mono text-xs text-slate-700 dark:text-slate-300">{h.domain_names.join(', ')}</span>
                <button
                  onClick={() => detachMutation.mutate(h.id)}
                  disabled={busy}
                  title={t('hosts.detach')}
                  aria-label={t('hosts.detach')}
                  className="flex h-5 w-5 items-center justify-center rounded-full text-slate-400 hover:bg-red-100 hover:text-red-600 dark:hover:bg-red-900/30 dark:hover:text-red-400 transition-colors disabled:opacity-50"
                >
                  <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </span>
            ))}
          </div>
        )}
      </div>

      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          {t('hosts.attachTitle')}
        </p>
        {attachable.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-500">{t('hosts.noAttachable')}</p>
        ) : (
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <select
                value={selectedHostId}
                onChange={(e) => setSelectedHostId(e.target.value)}
                className="w-full appearance-none rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 pl-3 pr-9 py-2 text-sm text-slate-900 dark:text-white focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 focus:outline-none"
              >
                <option value="">{t('hosts.selectHost')}</option>
                {attachable.map((h) => (
                  <option key={h.id} value={h.id}>{h.domain_names.join(', ')}</option>
                ))}
              </select>
              <svg className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
            </div>
            <button
              onClick={() => selectedHostId && attachMutation.mutate(selectedHostId)}
              disabled={!selectedHostId || busy}
              className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 010 5.656l-3 3a4 4 0 01-5.656-5.656l1.5-1.5m6.328-1.828a4 4 0 010-5.656l3-3a4 4 0 015.656 5.656l-1.5 1.5" /></svg>
              {t('hosts.attach')}
            </button>
          </div>
        )}
        <p className="mt-2 text-xs text-slate-400 dark:text-slate-500">{t('hosts.attachHint')}</p>
      </div>
    </div>
  );
}

export default AuthProviderHosts;

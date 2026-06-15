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
    <div className="space-y-3 px-6 py-4 bg-slate-50 dark:bg-slate-900/30">
      {error && (
        <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-3 py-2 rounded text-sm">
          {error}
        </div>
      )}

      <div>
        <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">
          {t('hosts.applied')} ({applied.length})
        </p>
        {applied.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">{t('hosts.noneApplied')}</p>
        ) : (
          <ul className="space-y-1">
            {applied.map((h) => (
              <li
                key={h.id}
                className="flex items-center justify-between bg-white dark:bg-slate-800 rounded border border-slate-200 dark:border-slate-700 px-3 py-1.5"
              >
                <span className="font-mono text-sm text-slate-700 dark:text-slate-300">
                  {h.domain_names.join(', ')}
                </span>
                <button
                  onClick={() => detachMutation.mutate(h.id)}
                  disabled={busy}
                  className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-xs font-medium disabled:opacity-50"
                >
                  {t('hosts.detach')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">
          {t('hosts.attachTitle')}
        </p>
        {attachable.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">{t('hosts.noAttachable')}</p>
        ) : (
          <div className="flex items-center gap-2">
            <select
              value={selectedHostId}
              onChange={(e) => setSelectedHostId(e.target.value)}
              className="flex-1 rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value="">{t('hosts.selectHost')}</option>
              {attachable.map((h) => (
                <option key={h.id} value={h.id}>{h.domain_names.join(', ')}</option>
              ))}
            </select>
            <button
              onClick={() => selectedHostId && attachMutation.mutate(selectedHostId)}
              disabled={!selectedHostId || busy}
              className="px-3 py-2 bg-indigo-600 text-white rounded-md text-sm hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              {t('hosts.attach')}
            </button>
          </div>
        )}
        <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">{t('hosts.attachHint')}</p>
      </div>
    </div>
  );
}

export default AuthProviderHosts;

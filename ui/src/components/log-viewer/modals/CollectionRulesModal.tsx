import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchLogRules, updateLogRules } from '../../../api/logs';
import type { HostLogRules } from '../../../types/log';
import { usePermissions } from '../../../hooks/usePermissions';
import { ModalShell } from '../../common/ModalShell';
import { IconButton, XIcon } from '../../common/listui';
import { HostLogRulesEditor } from './HostLogRulesEditor';

const SUMMARY_LIMIT = 6;

const skipsNothing = (r: HostLogRules) =>
  !r.skip_all && r.skip_statuses.length === 0 && r.skip_methods.length === 0 && r.skip_paths.length === 0;

/** What a host's rules leave out, in one line. */
function RulesSummary({ rules }: { rules: HostLogRules }) {
  const { t } = useTranslation('logs');
  if (rules.skip_all) {
    return (
      <span className="px-2 py-0.5 text-xs font-medium rounded bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
        {t('collectionRules.skipAll')}
      </span>
    );
  }
  const entries = [...rules.skip_statuses, ...rules.skip_methods, ...rules.skip_paths];
  if (entries.length === 0) {
    return <span className="text-xs text-slate-400 dark:text-slate-500">{t('collectionRules.storeAll')}</span>;
  }
  // A list takes up to 50 entries of each kind; the editor shows them all.
  const shown = entries.slice(0, SUMMARY_LIMIT);
  return (
    <span className="flex flex-wrap gap-1 min-w-0" title={entries.join(', ')}>
      {shown.map((e) => (
        <code
          key={e}
          className="px-1.5 py-0.5 text-xs rounded bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 break-all"
        >
          {e}
        </code>
      ))}
      {entries.length > shown.length && (
        <span className="px-1.5 py-0.5 text-xs text-slate-500 dark:text-slate-400">+{entries.length - shown.length}</span>
      )}
    </span>
  );
}

/**
 * The hosts' log rules (#347): which access log lines of each proxy host are
 * not stored. Opened from the access log toolbar; editing needs logs:write.
 */
export function CollectionRulesModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can('logs:write');
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const rulesQuery = useQuery({ queryKey: ['log-rules'], queryFn: fetchLogRules });
  const save = useMutation({
    mutationFn: ({ id, rules }: { id: string; rules: HostLogRules }) => updateLogRules(id, rules),
    onSuccess: () => {
      setEditing(null);
      setError(null);
      queryClient.invalidateQueries({ queryKey: ['log-rules'] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  const hosts = useMemo(() => {
    const q = search.trim().toLowerCase();
    const found = (rulesQuery.data ?? []).filter(
      (h) => !q || h.domain_names.some((d) => d.toLowerCase().includes(q)),
    );
    // Hosts with rules first, each group in the server's order (by domain).
    return [...found].sort((a, b) => Number(skipsNothing(a)) - Number(skipsNothing(b)));
  }, [rulesQuery.data, search]);

  const openEditor = (id: string) => {
    setEditing(id);
    setError(null);
  };

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-3xl">
      <div className="flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('collectionRules.title')}</h2>
          <IconButton onClick={onClose} title={t('collectionRules.cancel')}>
            <XIcon className="h-5 w-5" />
          </IconButton>
        </div>
        <div className="p-4 space-y-3 overflow-y-auto">
          <p className="text-sm text-slate-600 dark:text-slate-400">{t('collectionRules.intro')}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('collectionRules.caution')}</p>
          {!canWrite && <p className="text-xs text-amber-700 dark:text-amber-400">{t('collectionRules.readOnly')}</p>}
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('collectionRules.search')}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
          {rulesQuery.isLoading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-600" />
            </div>
          ) : rulesQuery.isError ? (
            <p className="text-sm text-red-600 dark:text-red-400">
              {rulesQuery.error instanceof Error ? rulesQuery.error.message : String(rulesQuery.error)}
            </p>
          ) : hosts.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400 italic py-4 text-center">
              {search.trim() ? t('collectionRules.noMatch') : t('collectionRules.empty')}
            </p>
          ) : (
            <ul className="space-y-2">
              {hosts.map((h) => (
                <li
                  key={h.proxy_host_id}
                  className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className="text-sm font-medium text-slate-900 dark:text-white truncate max-w-full"
                      title={h.domain_names.join(', ')}
                    >
                      {h.domain_names[0]}
                      {h.domain_names.length > 1 && ` +${h.domain_names.length - 1}`}
                    </span>
                    {!h.enabled && (
                      <span className="px-1.5 py-0.5 text-xs rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">
                        {t('collectionRules.disabledHost')}
                      </span>
                    )}
                    <RulesSummary rules={h} />
                    {canWrite && editing !== h.proxy_host_id && (
                      <button
                        type="button"
                        onClick={() => openEditor(h.proxy_host_id)}
                        className="ml-auto px-2.5 py-1 text-xs font-medium rounded-lg text-primary-700 dark:text-primary-300 hover:bg-primary-50 dark:hover:bg-primary-900/30"
                      >
                        {t('collectionRules.edit')}
                      </button>
                    )}
                  </div>
                  {editing === h.proxy_host_id && (
                    <HostLogRulesEditor
                      rules={h}
                      saving={save.isPending}
                      error={error}
                      onSave={(rules) => save.mutate({ id: h.proxy_host_id, rules })}
                      onCancel={() => setEditing(null)}
                    />
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </ModalShell>
  );
}

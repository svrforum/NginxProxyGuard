import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchErrorPages, resetErrorPage, saveErrorPage, type CustomErrorPage } from '../../../api/errorPages';
import { usePermissions } from '../../../hooks/usePermissions';
import { errorPageTemplate } from './errorPageTemplate';

/**
 * Custom HTML for NPG's own error pages (#335): the block page and the backend
 * error pages, on every proxy host and the default server. nginx serves them
 * with scripts blocked, so the preview runs sandboxed the same way.
 */
export default function ErrorPageSettings() {
  const { t } = useTranslation('settings');
  const { data, isLoading } = useQuery({ queryKey: ['error-pages'], queryFn: fetchErrorPages });

  if (isLoading || !data) {
    return <div className="text-sm text-slate-500 dark:text-slate-400">{t('errorPages.loading')}</div>;
  }
  const byStatus = new Map(data.pages.map((p) => [p.status_code, p]));
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('errorPages.title')}</h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t('errorPages.description')}</p>
        <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">{t('errorPages.noScripts')}</p>
      </div>
      {data.statuses.map((status) => (
        <ErrorPageCard key={`${status}-${byStatus.get(status)?.updated_at ?? ''}`} status={status} page={byStatus.get(status)} />
      ))}
    </div>
  );
}

function ErrorPageCard({ status, page }: { status: number; page?: CustomErrorPage }) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can('settings:write');
  const [html, setHtml] = useState(page?.html ?? '');
  const [preview, setPreview] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const done = (text: string) => {
    setMessage({ ok: true, text });
    queryClient.invalidateQueries({ queryKey: ['error-pages'] });
  };
  const fail = (err: unknown) => setMessage({ ok: false, text: err instanceof Error ? err.message : t('errorPages.saveError') });
  const save = useMutation({ mutationFn: () => saveErrorPage(status, html), onSuccess: () => done(t('errorPages.saved')), onError: fail });
  const reset = useMutation({ mutationFn: () => resetErrorPage(status), onSuccess: () => done(t('errorPages.resetDone')), onError: fail });
  const busy = save.isPending || reset.isPending;

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800" data-testid={`error-page-${status}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
          {status} · {t(`errorPages.status.${status}`)}
        </h3>
        <span
          className={`rounded-md px-2 py-0.5 text-xs font-medium ${page ? 'bg-indigo-50 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300' : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'}`}
        >
          {page ? t('errorPages.custom') : t('errorPages.builtIn')}
        </span>
      </div>

      <textarea
        value={html}
        onChange={(e) => setHtml(e.target.value)}
        readOnly={!canWrite}
        rows={10}
        spellCheck={false}
        aria-label={t('errorPages.htmlLabel', { status })}
        placeholder={t('errorPages.placeholder')}
        className="mt-3 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-800 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-200"
      />

      {preview && html.trim() && (
        <iframe
          title={t('errorPages.previewTitle', { status })}
          sandbox=""
          srcDoc={html}
          className="mt-3 h-72 w-full rounded-lg border border-slate-200 bg-white dark:border-slate-700"
        />
      )}

      {message && (
        <p className={`mt-2 text-sm ${message.ok ? 'text-green-700 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>{message.text}</p>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        {canWrite && !html.trim() && (
          <button
            type="button"
            onClick={() => setHtml(errorPageTemplate(status))}
            className="rounded-lg bg-slate-100 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
          >
            {t('errorPages.useTemplate')}
          </button>
        )}
        <button
          type="button"
          onClick={() => setPreview((v) => !v)}
          disabled={!html.trim()}
          className="rounded-lg bg-slate-100 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-200 disabled:opacity-50 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600"
        >
          {preview ? t('errorPages.hidePreview') : t('errorPages.preview')}
        </button>
        {canWrite && (
          <button
            type="button"
            onClick={() => {
              setMessage(null);
              save.mutate();
            }}
            disabled={busy || !html.trim() || html === page?.html}
            className="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            {t('errorPages.save')}
          </button>
        )}
        {canWrite && page && (
          <button
            type="button"
            onClick={() => {
              setMessage(null);
              reset.mutate();
            }}
            disabled={busy}
            className="rounded-lg px-3 py-2 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:text-red-400 dark:hover:bg-red-900/20"
          >
            {t('errorPages.reset')}
          </button>
        )}
      </div>
    </div>
  );
}

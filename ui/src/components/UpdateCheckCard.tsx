import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import { checkUpdate } from '../api/settings';

// Update-check card (#190). Shows installed vs latest release and, when behind,
// the documented manual update command. NPG does NOT update itself — display +
// guidance only.
export default function UpdateCheckCard() {
  const { t } = useTranslation('settings');
  // When the user clicks re-check, the next fetch forces a fresh backend fetch.
  // A ref (not state) so refetch() makes a SINGLE forced call, not two requests.
  const forceNext = useRef(false);

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['updateCheck'],
    queryFn: () => {
      const force = forceNext.current;
      forceNext.current = false;
      return checkUpdate(force);
    },
    staleTime: 60 * 60 * 1000, // backend caches for 1h
    refetchOnWindowFocus: false,
  });

  const busy = isLoading || isFetching;

  const handleRecheck = () => {
    forceNext.current = true;
    refetch();
  };

  const updateCmd = 'docker compose pull && docker compose up -d';

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">{t('system.update.title')}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{t('system.update.description')}</p>
        </div>
        <button
          onClick={handleRecheck}
          disabled={busy}
          className="shrink-0 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {busy ? t('system.update.checking') : t('system.update.checkUpdate')}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
        <span className="text-slate-600 dark:text-slate-400">
          {t('system.update.currentVersion')}:{' '}
          <span className="font-medium text-slate-900 dark:text-white">v{data?.current_version ?? '...'}</span>
        </span>
        {data && !data.check_failed && data.latest_version && (
          <span className="text-slate-600 dark:text-slate-400">
            {t('system.update.latestVersion')}:{' '}
            <span className="font-medium text-slate-900 dark:text-white">v{data.latest_version}</span>
          </span>
        )}
      </div>

      {data?.check_failed ? (
        <div className="text-sm text-amber-600 dark:text-amber-400">{t('system.update.checkFailed')}</div>
      ) : data?.update_available ? (
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            {t('system.update.newVersionAvailable', { version: `v${data.latest_version}` })}
          </div>
          {data.release_url && (
            <a
              href={data.release_url}
              target="_blank"
              rel="noopener noreferrer"
              className="block text-xs text-indigo-600 dark:text-indigo-400 hover:underline"
            >
              {t('system.update.releaseNotes')} →
            </a>
          )}
          <div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">{t('system.update.guidance')}</p>
            <code className="block text-xs bg-slate-100 dark:bg-slate-900 text-slate-800 dark:text-slate-200 rounded-lg px-3 py-2 font-mono select-all">
              {updateCmd}
            </code>
          </div>
        </div>
      ) : data ? (
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          {t('system.update.upToDate')}
        </div>
      ) : null}
    </div>
  );
}

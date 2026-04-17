import { useTranslation } from 'react-i18next';
import type { Log } from '../../../types/log';

export function LogRawBlock({ rawLog }: { rawLog?: string }) {
  const { t } = useTranslation('logs');
  if (!rawLog) return null;
  return (
    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
      <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.rawLog')}</label>
      <pre className="text-xs bg-slate-800 text-slate-200 p-3 rounded mt-1 overflow-x-auto overflow-y-hidden whitespace-pre-wrap break-all max-h-60">
        {rawLog}
      </pre>
    </div>
  );
}

export function ErrorMessageBlock({ errorMessage }: { errorMessage?: string }) {
  const { t } = useTranslation('logs');
  return (
    <div className="mb-4">
      <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.errorMsg')}</label>
      <p className="text-sm text-red-700 dark:text-red-400 font-mono bg-red-50 dark:bg-red-900/30 p-3 rounded">
        {errorMessage || '-'}
      </p>
    </div>
  );
}

interface ViewAccessLogButtonProps {
  onClick: () => void;
}

export function ViewAccessLogButton({ onClick }: ViewAccessLogButtonProps) {
  const { t } = useTranslation('logs');
  return (
    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
      <button
        onClick={onClick}
        className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors border border-slate-300 dark:border-slate-600"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
        </svg>
        {t('detail.viewAccessLog')}
      </button>
    </div>
  );
}

// URI row with "block URI" affordance
interface URIRowProps {
  log: Log;
  showBlockURIForm: boolean;
  onToggleBlockForm: () => void;
}

export function URIRow({ log, onToggleBlockForm }: URIRowProps) {
  const { t } = useTranslation('logs');
  return (
    <div className="mb-4">
      <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.uri')}</label>
      <div className="bg-slate-50 dark:bg-slate-800 p-2 rounded">
        {log.request_uri ? (
          <button
            onClick={onToggleBlockForm}
            className="group text-sm text-slate-900 dark:text-slate-200 font-mono break-all text-left hover:text-purple-700 dark:hover:text-purple-400 transition-colors"
            title={t('blockURI.clickToBlock')}
          >
            <span className="flex items-center gap-2">
              <span className="break-all">{log.request_uri}</span>
              <svg className="w-4 h-4 flex-shrink-0 text-purple-500 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </span>
          </button>
        ) : (
          <span className="text-sm text-slate-900 dark:text-slate-200 font-mono">-</span>
        )}
      </div>
    </div>
  );
}

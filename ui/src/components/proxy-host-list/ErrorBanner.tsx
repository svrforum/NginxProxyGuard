import { useTranslation } from 'react-i18next';

interface ErrorBannerProps {
  title: string;
  detail?: string;
  onRetry?: () => void;
  onDismiss?: () => void;
  className?: string;
}

// An error the operator can act on: what failed, the server's reason, and a
// way out (retry or dismiss).
export function ErrorBanner({ title, detail, onRetry, onDismiss, className = '' }: ErrorBannerProps) {
  const { t } = useTranslation('common');

  return (
    <div
      role="alert"
      className={`bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-sm text-red-700 dark:text-red-400 flex flex-wrap items-start justify-between gap-3 ${className}`}
    >
      <div className="min-w-0">
        <p className="font-medium">{title}</p>
        {detail && <p className="mt-1 text-xs break-all">{detail}</p>}
      </div>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="px-3 py-1.5 text-sm font-medium rounded-lg bg-white dark:bg-slate-800 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800 hover:bg-red-100 dark:hover:bg-red-900/40"
        >
          {t('buttons.retry')}
        </button>
      )}
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label={t('buttons.close')}
          className="p-1 rounded text-red-700 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-900/40"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </div>
  );
}

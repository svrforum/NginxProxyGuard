import { useState } from 'react';
import { useTranslation } from 'react-i18next';

// The clipboard API exists only in a secure context: over plain http the
// button says the copy failed, and the text beside it stays selectable.
export function CopyButton({ value }: { value: string }) {
  const { t } = useTranslation('common');
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
    setTimeout(() => setState('idle'), 1500);
  };

  const label =
    state === 'copied' ? t('messages.copySuccess') : state === 'failed' ? t('messages.copyFailed') : t('buttons.copy');
  const tone =
    state === 'copied'
      ? 'text-green-600 dark:text-green-400'
      : state === 'failed'
        ? 'text-red-600 dark:text-red-400'
        : 'text-slate-500 hover:text-slate-800 hover:bg-slate-200 dark:text-slate-400 dark:hover:text-slate-100 dark:hover:bg-slate-700';

  return (
    <button
      type="button"
      onClick={copy}
      title={label}
      aria-label={label}
      className={`flex-shrink-0 inline-flex items-center gap-1 px-1.5 py-1 rounded text-xs transition-colors ${tone}`}
    >
      {state === 'copied' ? (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
      {state !== 'idle' && <span>{label}</span>}
    </button>
  );
}

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CopyButton } from './CopyButton';

// A blocked request's URI is often an attack payload kilobytes long, so a
// long one shows its start and unfolds on request (#360).
const FOLD_AT = 200;

export function RequestURIBlock({ uri }: { uri?: string }) {
  const { t } = useTranslation('logs');
  const [open, setOpen] = useState(false);
  const long = !!uri && uri.length > FOLD_AT;

  return (
    <div className="mb-4">
      <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.requestURI')}</label>
      <div className="flex items-start gap-2 bg-slate-50 dark:bg-slate-800 p-2 rounded-lg">
        <p className="flex-1 min-w-0 text-sm text-slate-900 dark:text-slate-200 font-mono break-all">
          {!uri ? '-' : long && !open ? `${uri.slice(0, FOLD_AT)}…` : uri}
          {long && (
            <button
              type="button"
              onClick={() => setOpen(!open)}
              className="ml-2 font-sans text-xs text-blue-600 dark:text-blue-400 hover:underline"
            >
              {open ? t('detail.showLess') : t('detail.showAll')}
            </button>
          )}
        </p>
        {uri && <CopyButton value={uri} />}
      </div>
    </div>
  );
}

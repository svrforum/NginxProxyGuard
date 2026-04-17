import { useTranslation } from 'react-i18next';
import type { ProxyHost } from '../../types/proxy-host';

// ProxyHostRow.tsx - houses the per-row toggle confirmation dialog.
// The actual row rendering lives in ProxyHostTable; this file owns the
// modal surface that opens when toggling a host's enabled state.

interface ToggleConfirmDialogProps {
  host: ProxyHost;
  isPending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ToggleConfirmDialog({ host, isPending, onConfirm, onCancel }: ToggleConfirmDialogProps) {
  const { t } = useTranslation('proxyHost');

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-md overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
            {host.enabled ? t('actions.disableConfirmTitle') : t('actions.enableConfirmTitle')}
          </h3>
        </div>
        <div className="px-6 py-4">
          <p className="text-slate-600 dark:text-slate-400">
            {host.enabled
              ? t('actions.disableConfirmMessage', { domain: host.domain_names[0] })
              : t('actions.enableConfirmMessage', { domain: host.domain_names[0] })}
          </p>
        </div>
        <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            {t('common:buttons.cancel')}
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className={`px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors ${
              host.enabled ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700'
            } disabled:opacity-50`}
          >
            {isPending
              ? t('common:status.processing')
              : host.enabled
                ? t('actions.disable')
                : t('actions.enable')}
          </button>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ModalShell } from '../common/ModalShell'

interface DDNSRemovalConfirmModalProps {
  isOpen: boolean
  /** Modal heading — differs between "DDNS turned off" and "host deleted". */
  title: string
  /** One-line description of what is about to happen. */
  message: string
  /** Managed hostnames that would be removed, so the choice is informed. */
  hostnames: string[]
  /**
   * False for providers with no record-deletion concept (DuckDNS, Dynu);
   * undefined while the provider list has not resolved, so the dialog never
   * claims a provider cannot delete when it simply does not know yet.
   */
  providerCanDelete?: boolean
  /** Initial checkbox state — see the call sites for why they differ. */
  defaultRemoveProvider: boolean
  confirmLabel: string
  onCancel: () => void
  onConfirm: (removeProvider: boolean) => void
}

/**
 * Asks whether the host's managed DDNS records should also be deleted at the DNS
 * provider. Without this the records vanished from NPG while the public DNS entry
 * kept pointing at this server. (#219)
 */
export function DDNSRemovalConfirmModal({
  isOpen,
  title,
  message,
  hostnames,
  providerCanDelete,
  defaultRemoveProvider,
  confirmLabel,
  onCancel,
  onConfirm,
}: DDNSRemovalConfirmModalProps) {
  const { t } = useTranslation(['proxyHost', 'common'])
  const [removeProvider, setRemoveProvider] = useState(defaultRemoveProvider)

  // Reset on each open so a previous answer never carries over silently.
  useEffect(() => {
    if (isOpen) setRemoveProvider(defaultRemoveProvider)
  }, [isOpen, defaultRemoveProvider])

  return (
    <ModalShell
      isOpen={isOpen}
      onClose={onCancel}
      closeOnBackdrop={false}
      panelClassName="max-w-md"
      labelledById="ddns-removal-title"
    >
      <div className="p-6">
        <h3 id="ddns-removal-title" className="text-lg font-semibold text-slate-900 dark:text-white">{title}</h3>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{message}</p>

        {hostnames.length > 0 && (
          <ul className="mt-3 max-h-32 overflow-y-auto rounded-lg bg-slate-50 px-3 py-2 text-xs font-mono text-slate-600 dark:bg-slate-700/50 dark:text-slate-300">
            {hostnames.map((h) => (
              <li key={h} className="truncate">{h}</li>
            ))}
          </ul>
        )}

        {providerCanDelete === undefined ? (
          <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
            {t('ddnsRemoval.providerUnknown')}
          </p>
        ) : providerCanDelete ? (
          <label className="mt-4 flex cursor-pointer items-start gap-2.5">
            <input
              type="checkbox"
              checked={removeProvider}
              onChange={(e) => setRemoveProvider(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 dark:border-slate-600"
            />
            <span className="text-sm text-slate-700 dark:text-slate-200">
              {t('ddnsRemoval.removeProvider')}
              <span className="mt-0.5 block text-xs text-slate-500 dark:text-slate-400">
                {t('ddnsRemoval.removeProviderHint')}
              </span>
            </span>
          </label>
        ) : (
          <p className="mt-4 text-xs text-amber-600 dark:text-amber-400">
            {t('ddnsRemoval.providerCannotDelete')}
          </p>
        )}

        <div className="mt-6 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            {t('common:buttons.cancel')}
          </button>
          <button
            type="button"
            onClick={() => onConfirm(!!providerCanDelete && removeProvider)}
            className={`rounded-lg px-4 py-2 text-sm font-medium text-white transition-colors ${
              providerCanDelete && removeProvider
                ? 'bg-red-600 hover:bg-red-700'
                : 'bg-indigo-600 hover:bg-indigo-700'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </ModalShell>
  )
}

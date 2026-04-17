import { useTranslation } from 'react-i18next';
import { downloadBackup } from '../../api/settings';
import type { Backup } from '../../types/settings';

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function formatDate(dateStr: string, locale?: string): string {
  return new Date(dateStr).toLocaleString(locale);
}

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('settings');
  switch (status) {
    case 'completed':
      return <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 rounded text-xs">{t('backupManager.status.completed')}</span>;
    case 'in_progress':
      return <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded text-xs animate-pulse">{t('backupManager.status.inProgress')}</span>;
    case 'failed':
      return <span className="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 rounded text-xs">{t('backupManager.status.failed')}</span>;
    default:
      return <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300 rounded text-xs">{status}</span>;
  }
}

interface BackupStatsCardsProps {
  totalBackups: number;
  totalSize: number;
  lastBackup?: string;
  retentionDays?: number;
}

export function BackupStatsCards({ totalBackups, totalSize, lastBackup, retentionDays }: BackupStatsCardsProps) {
  const { t, i18n } = useTranslation('settings');
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
        <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.totalBackups')}</p>
        <p className="text-2xl font-bold dark:text-white">{totalBackups || 0}</p>
      </div>
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
        <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.totalSize')}</p>
        <p className="text-2xl font-bold dark:text-white">{formatBytes(totalSize || 0)}</p>
      </div>
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
        <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.lastBackup')}</p>
        <p className="text-lg font-medium dark:text-white">{lastBackup ? formatDate(lastBackup, i18n.language) : t('backupManager.stats.never')}</p>
      </div>
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4 transition-colors">
        <p className="text-gray-500 dark:text-gray-400 text-sm">{t('backupManager.stats.retention')}</p>
        <p className="text-2xl font-bold dark:text-white">{retentionDays || 30} {t('backupManager.stats.days')}</p>
      </div>
    </div>
  );
}

interface BackupListProps {
  backups?: Backup[];
  isLoading: boolean;
  restorePending: boolean;
  deletePending: boolean;
  onRestore: (backup: Backup) => void;
  onDelete: (id: string) => void;
}

export function BackupList({ backups, isLoading, restorePending, deletePending, onRestore, onDelete }: BackupListProps) {
  const { t, i18n } = useTranslation('settings');

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow transition-colors">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h2 className="text-lg font-semibold dark:text-white">{t('backupManager.history.title')}</h2>
      </div>

      {isLoading ? (
        <div className="p-8 text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
        </div>
      ) : backups && backups.length > 0 ? (
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {backups.map((backup) => (
            <div key={backup.id} className="p-4 hover:bg-gray-50 dark:hover:bg-slate-700/50 transition-colors">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium dark:text-white">{backup.filename}</span>
                    <StatusBadge status={backup.status} />
                  </div>
                  <div className="mt-1 text-sm text-gray-500 dark:text-gray-400 flex flex-wrap gap-4">
                    <span>{formatDate(backup.created_at, i18n.language)}</span>
                    <span>{formatBytes(backup.file_size)}</span>
                    <span className="capitalize">{backup.backup_type}</span>
                  </div>
                  <div className="mt-1 text-sm text-gray-500 dark:text-gray-400 flex gap-2">
                    {backup.includes_config && <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">{t('backupManager.labels.config')}</span>}
                    {backup.includes_certificates && <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">{t('backupManager.labels.certs')}</span>}
                    {backup.includes_database && <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs">{t('backupManager.labels.database')}</span>}
                  </div>
                  {backup.description && (
                    <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">{backup.description}</p>
                  )}
                  {backup.error_message && (
                    <p className="mt-1 text-sm text-red-600 dark:text-red-400">{backup.error_message}</p>
                  )}
                </div>
                <div className="flex gap-2">
                  {backup.status === 'completed' && (
                    <>
                      <button
                        onClick={() => downloadBackup(backup.id, backup.filename)}
                        className="px-3 py-1.5 text-sm bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-200 rounded-lg transition-colors"
                      >
                        {t('backupManager.buttons.download')}
                      </button>
                      <button
                        onClick={() => onRestore(backup)}
                        disabled={restorePending}
                        className="px-3 py-1.5 text-sm bg-amber-100 dark:bg-amber-900/30 hover:bg-amber-200 dark:hover:bg-amber-900/50 text-amber-800 dark:text-amber-400 rounded-lg disabled:opacity-50 transition-colors"
                      >
                        {t('backupManager.buttons.restore')}
                      </button>
                    </>
                  )}
                  <button
                    onClick={() => onDelete(backup.id)}
                    disabled={deletePending}
                    className="px-3 py-1.5 text-sm bg-red-100 dark:bg-red-900/30 hover:bg-red-200 dark:hover:bg-red-900/50 text-red-800 dark:text-red-400 rounded-lg disabled:opacity-50 transition-colors"
                  >
                    {t('backupManager.buttons.delete')}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="p-8 text-center text-gray-500 dark:text-gray-400">
          {t('backupManager.history.empty')}
        </div>
      )}
    </div>
  );
}

// Backup Progress Modal Component
export function BackupProgressModal({
  backupId,
  backups,
  onClose,
}: {
  backupId: string;
  backups: Backup[];
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation('settings');
  const currentBackup = backups.find((b) => b.id === backupId);
  const status = currentBackup?.status || 'in_progress';
  const isCompleted = status === 'completed';
  const isFailed = status === 'failed';

  const steps = [
    { key: 'init', label: t('backupManager.progress.initializing') },
    { key: 'database', label: t('backupManager.progress.exportingDatabase') },
    { key: 'config', label: t('backupManager.progress.exportingConfig') },
    { key: 'certs', label: t('backupManager.progress.exportingCerts') },
    { key: 'archive', label: t('backupManager.progress.creatingArchive') },
    { key: 'complete', label: t('backupManager.progress.complete') },
  ];

  // Simulate progress based on status
  const currentStep = isCompleted ? 5 : isFailed ? -1 : 2;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md p-6 transition-colors">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold dark:text-white">
            {isCompleted
              ? t('backupManager.progress.titleComplete')
              : isFailed
                ? t('backupManager.progress.titleFailed')
                : t('backupManager.progress.title')}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Progress Steps */}
        <div className="space-y-3 mb-6">
          {steps.map((step, index) => {
            const isActive = index === currentStep;
            const isDone = index < currentStep;
            const isPending = index > currentStep;

            return (
              <div key={step.key} className="flex items-center gap-3">
                <div
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                    isDone
                      ? 'bg-green-500 text-white'
                      : isActive
                        ? 'bg-blue-500 text-white animate-pulse'
                        : isFailed && index === currentStep + 1
                          ? 'bg-red-500 text-white'
                          : 'bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400'
                  }`}
                >
                  {isDone ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : isFailed && index === currentStep + 1 ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  ) : (
                    index + 1
                  )}
                </div>
                <span
                  className={`text-sm ${
                    isDone
                      ? 'text-green-600 dark:text-green-400'
                      : isActive
                        ? 'text-blue-600 dark:text-blue-400 font-medium'
                        : isPending
                          ? 'text-gray-400 dark:text-gray-500'
                          : 'text-gray-700 dark:text-gray-300'
                  }`}
                >
                  {step.label}
                </span>
              </div>
            );
          })}
        </div>

        {/* Error Message */}
        {isFailed && currentBackup?.error_message && (
          <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg">
            <p className="text-sm text-red-700 dark:text-red-400">{currentBackup.error_message}</p>
          </div>
        )}

        {/* Completion Info */}
        {isCompleted && currentBackup && (
          <div className="mb-4 p-3 bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 rounded-lg">
            <p className="text-sm text-green-700 dark:text-green-400">
              {t('backupManager.progress.completedAt')}: {formatDate(currentBackup.completed_at || '', i18n.language)}
            </p>
          </div>
        )}

        {/* Close Button */}
        <div className="flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-700"
          >
            {t('backupManager.buttons.close')}
          </button>
        </div>
      </div>
    </div>
  );
}

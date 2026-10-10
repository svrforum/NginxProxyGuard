import { useTranslation } from 'react-i18next';
import type { RawLogUsage } from '../../types/rawLogFiles';
import { formatFileSize } from './shared';

interface RawLogUsageEstimateProps {
  usage: RawLogUsage | undefined;
  /** Retention being edited (falls back to the saved one). */
  retentionDays: number;
}

/**
 * Disk use the raw logs will settle at, from real rotated files: the average
 * per day over the last 7 days × the retention being edited, plus the live
 * files and the newest rotated file not compressed yet. It updates while the
 * operator edits the retention, and warns when it would not fit on the disk.
 */
export default function RawLogUsageEstimate({ usage, retentionDays }: RawLogUsageEstimateProps) {
  const { t } = useTranslation('logs');
  if (!usage) return null;

  const current = usage.live_bytes + usage.pending_bytes;
  const hasBasis = usage.basis !== 'none';
  const retention = Number.isFinite(retentionDays) && retentionDays > 0 ? retentionDays : usage.retention_days;
  // While the archive takes them, rotated files leave the log disk once
  // settled; the archive card shows what they take there. Switched on but not
  // usable (not mounted, full, stalled), it takes nothing and they stay here.
  const archiveOn = usage.archive_in_use;
  const projected = (archiveOn ? 0 : usage.avg_daily_bytes * retention) + current;
  // The raw logs already on the disk are part of the projection, so they count
  // as room it can use.
  const room = usage.local_free_bytes !== undefined ? usage.local_free_bytes + usage.local_bytes : undefined;
  const exceeds = hasBasis && room !== undefined && projected > room;

  return (
    <div
      data-testid="raw-log-usage-estimate"
      className={`rounded-lg p-3 text-sm space-y-1 ${exceeds
        ? 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
        : 'bg-slate-50 dark:bg-slate-700/50'}`}
    >
      <div>
        <span className="text-slate-600 dark:text-slate-400">{t('rawFiles.settings.estimatedSize')}: </span>
        <span className="font-semibold text-slate-800 dark:text-slate-200">
          {hasBasis || archiveOn ? `≈ ${formatFileSize(projected)}` : formatFileSize(current)}
        </span>
      </div>
      {archiveOn ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('rawFiles.estimate.archiveOn', { current: formatFileSize(current) })}</p>
      ) : hasBasis ? (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {t('rawFiles.estimate.formula', {
            daily: formatFileSize(usage.avg_daily_bytes),
            basis: t('rawFiles.estimate.basis', { days: usage.basis_days }),
            retention,
            current: formatFileSize(current),
          })}
        </p>
      ) : (
        <p className="text-xs text-slate-500 dark:text-slate-400">{t('rawFiles.estimate.none')}</p>
      )}
      {usage.archive_enabled && !archiveOn && (
        <p className="text-xs text-amber-700 dark:text-amber-400">{t('rawFiles.estimate.archiveNotInUse')}</p>
      )}
      <p className="text-xs text-slate-500 dark:text-slate-400">
        {t('rawFiles.estimate.current', { count: usage.local_files, size: formatFileSize(usage.local_bytes) })}
        {usage.local_free_bytes !== undefined && usage.local_total_bytes !== undefined && (
          <>
            {' · '}
            {t('rawFiles.estimate.disk', {
              fs: usage.local_fs_type || '?',
              free: formatFileSize(usage.local_free_bytes),
              total: formatFileSize(usage.local_total_bytes),
            })}
          </>
        )}
      </p>
      {exceeds && (
        <p role="alert" className="text-xs font-medium text-red-700 dark:text-red-300">
          {t('rawFiles.estimate.exceedsFree', { free: formatFileSize(usage.local_free_bytes ?? 0) })}
        </p>
      )}
    </div>
  );
}

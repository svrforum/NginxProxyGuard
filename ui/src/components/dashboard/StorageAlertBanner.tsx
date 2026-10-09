import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import type { EmergencyCompressionStatus, StorageStatus } from '../../types/storage';
import { usePermissions } from '../../hooks/usePermissions';

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * A disk NPG writes to is past the warning line (D4). Shown above everything on
 * the dashboard because a full disk is what takes a home server down: the
 * database stops committing, and with it logging, sign-in and alerting.
 */
export default function StorageAlertBanner({ storage }: { storage?: StorageStatus }) {
  const { t } = useTranslation('dashboard');
  const { canArea } = usePermissions();
  if (!storage || storage.level === 'ok') return null;
  const worst = storage.filesystems.find((f) => f.level === storage.level) ?? storage.filesystems[0];
  if (!worst) return null;

  const critical = storage.level === 'critical';
  const roles = worst.roles.map((r) => t(`storage.roles.${r}`, { defaultValue: r })).join(', ');
  const tone = critical
    ? 'border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-900/20 dark:text-red-100'
    : 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-100';

  // Early compression only frees the database's disk, so it is only worth a
  // line when that is the disk in trouble.
  const emergencyText = (em?: EmergencyCompressionStatus): string | null => {
    if (!em) return null;
    if (em.mode === 'off') return t('storage.emergency.off');
    switch (em.state) {
      case 'running':
        return t('storage.emergency.running', { done: em.chunks_done, total: em.chunks_total });
      case 'done':
        if (em.reason === 'dry_run') return t('storage.emergency.dryRun', { count: em.chunks_total });
        if (em.chunks_done > 0) return t('storage.emergency.done', { count: em.chunks_done, freed: formatBytes(em.freed_bytes) });
        return t('storage.emergency.blocked.nothing_to_compress');
      case 'blocked':
        return t(`storage.emergency.blocked.${em.reason || 'error'}`, { defaultValue: t('storage.emergency.blocked.error') });
      default:
        return null; // idle: no pass has started yet
    }
  };
  const emergency = critical && worst.roles.includes('db') ? emergencyText(storage.emergency) : null;

  return (
    <div role="alert" data-testid="storage-alert" data-level={storage.level} className={`rounded-lg border p-4 ${tone}`}>
      <p className="font-semibold">{t(critical ? 'storage.banner.critical' : 'storage.banner.low')}</p>
      <p className="mt-1 text-sm">
        {t('storage.banner.usage', {
          percent: worst.used_percent.toFixed(1),
          free: formatBytes(worst.avail_bytes),
          total: formatBytes(worst.total_bytes),
          roles,
        })}
        <span className="ml-1 break-all font-mono text-xs opacity-75">{worst.path}</span>
      </p>
      {worst.days_to_full != null && worst.growth_per_day_bytes != null && worst.growth_per_day_bytes > 0 && (
        <p className="mt-1 text-sm">
          {t('storage.banner.forecast', {
            growth: formatBytes(worst.growth_per_day_bytes),
            days: worst.days_to_full < 1 ? '<1' : Math.round(worst.days_to_full),
          })}
        </p>
      )}
      {emergency && (
        <p data-testid="storage-emergency" className="mt-1 text-sm">{emergency}</p>
      )}
      <p className="mt-2 text-xs opacity-80">
        {t('storage.banner.hint')}
        {canArea('settings') && (
          <>
            {' '}
            <Link to="/settings/maintenance" className="underline">{t('storage.banner.retentionLink')}</Link>
            {' · '}
            <Link to="/settings/notifications" className="underline">{t('storage.banner.alertsLink')}</Link>
          </>
        )}
      </p>
    </div>
  );
}

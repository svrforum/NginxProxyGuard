import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getSystemSettings, updateSystemSettings } from '../../api/settings';
import { checkRawLogArchive, initRawLogArchive, runRawLogArchive, RawLogArchiveError } from '../../api/rawLogArchive';
import type { RawLogArchiveStatus, RawLogUsage } from '../../types/rawLogFiles';
import type { UpdateSystemSettingsRequest } from '../../types/settings';
import { ModalShell } from '../common/ModalShell';
import { usePermissions } from '../../hooks/usePermissions';
import { RAW_LOG_ARCHIVE_RETENTION, formatFileSize, type RawLogMessage } from './shared';

interface RawLogArchiveCardProps {
  archive: RawLogArchiveStatus | undefined;
  usage: RawLogUsage | undefined;
  onMessage: (message: RawLogMessage) => void;
}

const statusTone: Record<string, string> = {
  ready: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300',
  disabled: 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300',
};
const warnTone = 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300';

/**
 * The archive directory: another disk or a NAS share bound into the API
 * container. "Check" probes it, "Use this directory" writes the marker that
 * allows NPG to write there, and the switch moves settled rotated files.
 */
export default function RawLogArchiveCard({ archive, usage, onMessage }: RawLogArchiveCardProps) {
  const { t, i18n } = useTranslation('logs');
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can('settings:write');
  const [edited, setEdited] = useState<UpdateSystemSettingsRequest>({});
  const [probe, setProbe] = useState<RawLogArchiveStatus | null>(null);
  const [confirmInit, setConfirmInit] = useState(false);

  const { data: settings } = useQuery({ queryKey: ['systemSettings'], queryFn: getSystemSettings });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['logFiles'] });
  const fail = (error: Error) => {
    if (error instanceof RawLogArchiveError && error.archive) setProbe(error.archive);
    onMessage({ type: 'error', text: error.message });
  };

  const checkMutation = useMutation({
    mutationFn: checkRawLogArchive,
    onSuccess: (st) => setProbe(st),
    onError: fail,
  });
  const initMutation = useMutation({
    mutationFn: initRawLogArchive,
    onSuccess: (st) => {
      setProbe(st);
      setConfirmInit(false);
      refresh();
      onMessage({ type: 'success', text: t('rawFiles.archive.initDone') });
    },
    onError: (error: Error) => {
      setConfirmInit(false);
      fail(error);
    },
  });
  const runMutation = useMutation({
    mutationFn: runRawLogArchive,
    onSuccess: () => {
      onMessage({ type: 'info', text: t('rawFiles.archive.runStarted') });
      setTimeout(refresh, 3000);
    },
    onError: fail,
  });
  const saveMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      refresh();
      setEdited({});
      onMessage({ type: 'success', text: t('rawFiles.saveSuccess') });
    },
    onError: (error: Error) => onMessage({ type: 'error', text: t('rawFiles.saveFail', { error: error.message }) }),
  });

  const enabled = edited.raw_log_archive_enabled ?? settings?.raw_log_archive_enabled ?? false;
  const retention = edited.raw_log_archive_retention_days ?? settings?.raw_log_archive_retention_days ?? 365;
  const retentionInvalid = 'raw_log_archive_retention_days' in edited &&
    !(Number.isInteger(retention) && retention >= RAW_LOG_ARCHIVE_RETENTION.min && retention <= RAW_LOG_ARCHIVE_RETENTION.max);
  const shown = probe ?? archive;
  const busy = checkMutation.isPending || initMutation.isPending || runMutation.isPending;

  const projected = usage && usage.basis !== 'none' && Number.isFinite(retention) ? usage.avg_daily_bytes * retention : undefined;
  const fits = projected === undefined || shown?.free_bytes === undefined || projected <= shown.free_bytes + (usage?.archive_bytes ?? 0);

  const fsLine = (st: RawLogArchiveStatus) =>
    st.total_bytes
      ? t('rawFiles.archive.fs', { fs: st.fs_type || '?', free: formatFileSize(st.free_bytes ?? 0), total: formatFileSize(st.total_bytes) })
      : '';

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('rawFiles.archive.title')}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('rawFiles.archive.description', { dir: shown?.dir || '/archive' })}</p>
        </div>
        {canWrite && (
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => checkMutation.mutate()}
              disabled={busy}
              className="px-3 py-2 text-sm font-medium bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-600 disabled:opacity-50 transition-colors"
            >
              {checkMutation.isPending ? t('rawFiles.archive.actions.checking') : t('rawFiles.archive.actions.check')}
            </button>
            {shown?.mounted && shown.marker !== 'ours' && shown.status !== 'stalled' && (
              <button
                onClick={() => setConfirmInit(true)}
                disabled={busy}
                className="px-3 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {t('rawFiles.archive.actions.init')}
              </button>
            )}
            {settings?.raw_log_archive_enabled && shown?.status === 'ready' && (
              <button
                onClick={() => runMutation.mutate()}
                disabled={busy || shown.running}
                className="px-3 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {t('rawFiles.archive.actions.run')}
              </button>
            )}
          </div>
        )}
      </div>

      {shown && (
        <div data-testid="raw-log-archive-status" className="rounded-lg bg-slate-50 dark:bg-slate-700/50 p-3 text-sm space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${statusTone[shown.status] ?? warnTone}`}>
              {t(`rawFiles.archive.status.${shown.status}`, { defaultValue: shown.status })}
            </span>
            <span className="text-xs text-slate-500 dark:text-slate-400 break-all">{shown.dir}</span>
            {fsLine(shown) && <span className="text-xs text-slate-500 dark:text-slate-400">· {fsLine(shown)}</span>}
          </div>
          {shown.status !== 'ready' && shown.status !== 'disabled' && (
            <p className="text-xs text-slate-600 dark:text-slate-300">{t(`rawFiles.archive.help.${shown.status}`, { defaultValue: shown.detail ?? '' })}</p>
          )}
          {shown.status === 'disabled' && shown.marker === 'ours' && (
            <p className="text-xs text-slate-600 dark:text-slate-300">{t('rawFiles.archive.help.readyToEnable')}</p>
          )}
          {shown.last_move_at && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {t('rawFiles.archive.lastMove', { when: new Date(shown.last_move_at).toLocaleString(i18n.language), count: shown.last_moved })}
            </p>
          )}
          {shown.enabled && shown.pending_files > 0 && (
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('rawFiles.archive.pending', { count: shown.pending_files })}</p>
          )}
          {shown.last_error && <p className="text-xs text-red-600 dark:text-red-400 break-all">{shown.last_error}</p>}
        </div>
      )}

      <div className="space-y-3">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            disabled={!canWrite}
            onChange={(e) => setEdited((prev) => ({ ...prev, raw_log_archive_enabled: e.target.checked }))}
            className="mt-0.5 w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700"
          />
          <div>
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('rawFiles.archive.toggle')}</span>
            <p className="text-xs text-slate-500 dark:text-slate-400">{t('rawFiles.archive.toggleDesc')}</p>
          </div>
        </label>

        <div>
          <label htmlFor="raw-log-archive-retention" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            {t('rawFiles.archive.retention')}
          </label>
          <input
            id="raw-log-archive-retention"
            type="number"
            min={RAW_LOG_ARCHIVE_RETENTION.min}
            max={RAW_LOG_ARCHIVE_RETENTION.max}
            value={Number.isFinite(retention) ? retention : ''}
            disabled={!canWrite}
            aria-invalid={retentionInvalid}
            onChange={(e) => setEdited((prev) => ({ ...prev, raw_log_archive_retention_days: e.target.value === '' ? Number.NaN : Number(e.target.value) }))}
            className={`w-32 px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white ${retentionInvalid ? 'border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
          />
          {retentionInvalid && (
            <p className="text-xs text-red-600 dark:text-red-400 mt-1">
              {t('rawFiles.settings.rangeHint', { min: RAW_LOG_ARCHIVE_RETENTION.min, max: RAW_LOG_ARCHIVE_RETENTION.max })}
            </p>
          )}
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('rawFiles.archive.localRetentionNote')}</p>
          {projected !== undefined && enabled && (
            <p className={`text-xs mt-1 ${fits ? 'text-slate-500 dark:text-slate-400' : 'text-red-600 dark:text-red-400 font-medium'}`}>
              {t(fits ? 'rawFiles.archive.estimate' : 'rawFiles.archive.estimateExceeds', {
                size: formatFileSize(projected),
                free: formatFileSize(shown?.free_bytes ?? 0),
              })}
            </p>
          )}
        </div>

        {canWrite && (
          <button
            onClick={() => saveMutation.mutate(edited)}
            disabled={Object.keys(edited).length === 0 || retentionInvalid || saveMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 transition-colors"
          >
            {saveMutation.isPending ? t('rawFiles.settings.saving') : t('rawFiles.settings.save')}
          </button>
        )}
      </div>

      <ModalShell isOpen={confirmInit} onClose={() => setConfirmInit(false)} panelClassName="max-w-md" labelledById="raw-log-archive-init-title">
        <div className="p-6 space-y-3">
          <h3 id="raw-log-archive-init-title" className="text-lg font-semibold text-slate-800 dark:text-white">{t('rawFiles.archive.initConfirmTitle')}</h3>
          <p className="text-sm text-slate-600 dark:text-slate-400 break-all">
            {t('rawFiles.archive.initConfirm', { dir: shown?.dir ?? '', fs: shown?.fs_type || '?', total: formatFileSize(shown?.total_bytes ?? 0), free: formatFileSize(shown?.free_bytes ?? 0) })}
          </p>
          {shown?.marker === 'foreign' && (
            <p className="text-sm font-medium text-amber-700 dark:text-amber-300">{t('rawFiles.archive.initForeign')}</p>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              onClick={() => setConfirmInit(false)}
              className="px-4 py-2 text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
            >
              {t('rawFiles.modal.cancel')}
            </button>
            <button
              onClick={() => initMutation.mutate()}
              disabled={initMutation.isPending}
              className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {t('rawFiles.archive.actions.init')}
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  );
}

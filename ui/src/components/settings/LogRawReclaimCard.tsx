import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getRawLogReclaimStatus, startRawLogReclaim, stopRawLogReclaim } from '../../api/rawLogReclaim';
import { ApiError } from '../../api/client';
import type { LogRawReclaimStatus, RawLogReclaimJobStatus } from '../../types/rawLogReclaim';
import { usePermissions } from '../../hooks/usePermissions';
import { ModalShell } from '../common/ModalShell';

const QUERY_KEY = ['rawLogReclaim'];

function formatBytes(bytes: number | undefined): string {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Days are UTC chunks on the server; show the same date it logs, whatever
// offset the timestamp carries.
function dayOf(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso.slice(0, 10) : d.toISOString().slice(0, 10);
}

// In the UI's language, not the browser's: the sentence around it is.
function timeOf(iso: string, lang: string): string {
  return new Date(iso).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit' });
}

const STATUS_TONE: Record<RawLogReclaimJobStatus, string> = {
  idle: 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300',
  running: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  paused: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  done: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
};

/**
 * Settings > Maintenance: the opt-in removal of the raw_log copies kept in old
 * compressed log history. Irreversible for the database copy, so Start goes
 * through a confirmation that names what is lost.
 */
export default function LogRawReclaimCard() {
  const { t, i18n } = useTranslation(['settings', 'common']);
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can('settings:write');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [maxChunks, setMaxChunks] = useState('');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const k = (key: string) => `system.maintenance.rawReclaim.${key}`;

  const { data: st, isLoading, error } = useQuery({
    queryKey: QUERY_KEY,
    // Measuring what is left costs the server a pass over the compressed days
    // (cached 10 minutes there); skip it while the job runs and this polls.
    queryFn: () => {
      const prev = queryClient.getQueryData<LogRawReclaimStatus>(QUERY_KEY);
      return getRawLogReclaimStatus(prev?.status !== 'running');
    },
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 5000 : false),
  });

  // When a run ends, measure once more: what is left has changed.
  const lastStatus = useRef<RawLogReclaimJobStatus | undefined>(undefined);
  useEffect(() => {
    const prev = lastStatus.current;
    lastStatus.current = st?.status;
    if (prev === 'running' && st && st.status !== 'running') {
      queryClient.invalidateQueries({ queryKey: QUERY_KEY });
    }
  }, [st, queryClient]);

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), type === 'success' ? 3000 : 8000);
  };

  const errorText = (err: unknown): string => {
    if (err instanceof ApiError && err.code) {
      const known = ['already_running', 'unsupported', 'free_space_unknown', 'insufficient_space'];
      if (known.includes(err.code)) return t(k(`errors.${err.code}`));
    }
    return t(k('errors.generic'), { message: err instanceof Error ? err.message : String(err) });
  };

  const startMutation = useMutation({
    mutationFn: (max?: number) => startRawLogReclaim(max ? { max_chunks: max } : {}),
    onSuccess: (data) => {
      queryClient.setQueryData(QUERY_KEY, data);
      setConfirmOpen(false);
      setMaxChunks('');
    },
    onError: (err) => {
      setConfirmOpen(false);
      showMessage('error', errorText(err));
      queryClient.invalidateQueries({ queryKey: QUERY_KEY });
    },
  });

  const stopMutation = useMutation({
    mutationFn: stopRawLogReclaim,
    onSuccess: (data) => queryClient.setQueryData(QUERY_KEY, data),
    onError: (err) => showMessage('error', errorText(err)),
  });

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5">
        <div className="h-24 animate-pulse rounded-lg bg-slate-100 dark:bg-slate-700/50" />
      </div>
    );
  }
  if (error || !st) {
    return (
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5">
        <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t(k('title'))}</h3>
        <p className="mt-2 text-sm text-red-600 dark:text-red-400">{errorText(error)}</p>
      </div>
    );
  }

  const running = st.status === 'running';
  const resumable = st.status === 'paused' || st.status === 'failed';
  const progressBase = st.reclaimed_bytes + st.remaining_raw_bytes;
  const progressPct = progressBase > 0 ? Math.min(100, Math.round((st.reclaimed_bytes / progressBase) * 100)) : 0;
  const freeKnown = st.free_bytes !== undefined;
  const short = freeKnown && st.required_free_bytes > 0 && (st.free_bytes ?? 0) < st.required_free_bytes;
  const nothingLeft = st.estimated_reclaimable_bytes !== undefined && st.estimated_reclaimable_bytes === 0 && st.chunks_pending === 0;
  const startDisabled = !st.supported || !freeKnown || short || startMutation.isPending || (nothingLeft && !resumable);

  const confirmStart = () => {
    const n = parseInt(maxChunks, 10);
    startMutation.mutate(Number.isFinite(n) && n >= 1 ? n : undefined);
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t(k('title'))}</h3>
        </div>
        <span className={`shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold ${STATUS_TONE[st.status] ?? STATUS_TONE.idle}`}>
          {t(k(`status.${st.status}`))}
        </span>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400">{t(k('description'))}</p>
      <p className="mt-1 text-xs font-medium text-amber-700 dark:text-amber-400">{t(k('irreversible'))}</p>

      {message && (
        <div className={`mt-4 px-4 py-3 rounded-lg text-sm font-medium ${message.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'}`}>
          {message.text}
        </div>
      )}

      {!st.supported && (
        <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-300">
          <p className="font-semibold">{t(k('unsupported'))}</p>
          {st.unsupported_reason && <p className="mt-1">{t(k(`unsupportedReasons.${st.unsupported_reason}`))}</p>}
        </div>
      )}

      {/* Figures */}
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-600 dark:bg-slate-700/50">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">{t(k('estimate'))}</p>
          {st.estimated_reclaimable_bytes === undefined ? (
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{st.supported ? t(k('estimating')) : '—'}</p>
          ) : st.estimated_reclaimable_bytes === 0 ? (
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{t(k('estimateNone'))}</p>
          ) : (
            <>
              <p className="mt-1 text-lg font-semibold text-slate-800 dark:text-white">{formatBytes(st.estimated_reclaimable_bytes)}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t(k('estimateDays'), { count: st.estimate_chunks ?? 0 })}</p>
            </>
          )}
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-600 dark:bg-slate-700/50">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">{t(k('modsecKept'))}</p>
          <p className="mt-1 text-lg font-semibold text-slate-800 dark:text-white">
            {st.modsec_raw_bytes === undefined ? '—' : formatBytes(st.modsec_raw_bytes)}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">{t(k('modsecKeptHint'))}</p>
        </div>
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-600 dark:bg-slate-700/50">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">{t(k('freeSpace'))}</p>
          <p className={`mt-1 text-lg font-semibold ${short ? 'text-red-600 dark:text-red-400' : 'text-slate-800 dark:text-white'}`}>
            {freeKnown ? formatBytes(st.free_bytes) : t(k('freeUnknownShort'))}
          </p>
          {st.required_free_bytes > 0 && (
            <p className="text-xs text-slate-500 dark:text-slate-400">{t(k('required'), { size: formatBytes(st.required_free_bytes) })}</p>
          )}
        </div>
      </div>

      {/* Progress */}
      {st.chunks_total > 0 && (
        <div className="mt-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
            <span className="font-medium text-slate-700 dark:text-slate-300">{t(k('progress'))}</span>
            <span className="text-slate-500 dark:text-slate-400">
              {t(k('progressDays'), { done: st.chunks_done, total: st.chunks_total })}
              {' · '}
              {t(k('reclaimed'), { size: formatBytes(st.reclaimed_bytes) })}
            </span>
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700" role="progressbar"
            aria-valuemin={0} aria-valuemax={100} aria-valuenow={progressPct}>
            <div className="h-full rounded-full bg-blue-600 transition-all" style={{ width: `${progressPct}%` }} />
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
            {st.remaining_raw_bytes > 0 && <span>{t(k('remaining'), { size: formatBytes(st.remaining_raw_bytes) })}</span>}
            {st.chunks_skipped > 0 && <span>{t(k('skipped'), { count: st.chunks_skipped })}</span>}
            {st.chunks_failed > 0 && <span className="text-red-600 dark:text-red-400">{t(k('failedDays'), { count: st.chunks_failed })}</span>}
          </div>
        </div>
      )}

      {/* Current day and step */}
      {running && (
        <div className="mt-4 rounded-lg border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800 dark:border-blue-800 dark:bg-blue-900/20 dark:text-blue-300">
          {st.resume_at ? (
            <p>{t(k('resumeAt'), { time: timeOf(st.resume_at, i18n.language) })}</p>
          ) : st.current_chunk ? (
            <>
              <p className="font-medium">{t(k('current'), { day: dayOf(st.current_chunk.range_start) })}</p>
              <p className="mt-0.5">
                {t(k(`steps.${st.current_chunk.step}`))}
                <span className="ml-2 text-xs opacity-75">{t(k('since'), { time: timeOf(st.current_chunk.since, i18n.language) })}</span>
              </p>
            </>
          ) : (
            <p>{t(k('preparing'))}</p>
          )}
        </div>
      )}

      {st.last_error && (
        <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
          <p className="font-semibold">{t(k('lastError'))}</p>
          <p className="mt-1 break-words">{st.last_error}</p>
        </div>
      )}

      {st.supported && !running && !freeKnown && st.estimated_at && (
        <p className="mt-4 text-sm text-amber-700 dark:text-amber-400">{t(k('freeUnknown'))}</p>
      )}
      {st.supported && !running && short && (
        <p className="mt-4 text-sm text-red-600 dark:text-red-400">
          {t(k('needSpace'), { required: formatBytes(st.required_free_bytes), free: formatBytes(st.free_bytes) })}
        </p>
      )}

      {/* Actions */}
      <div className="mt-4 flex flex-wrap items-center justify-end gap-3">
        {!canWrite && <span className="text-xs text-slate-500 dark:text-slate-400">{t(k('readOnly'))}</span>}
        {canWrite && running && (
          <button
            type="button"
            onClick={() => stopMutation.mutate()}
            disabled={stopMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-100 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700 disabled:opacity-50 transition-colors"
          >
            {stopMutation.isPending ? t(k('stopping')) : t(k('stop'))}
          </button>
        )}
        {canWrite && !running && (
          <button
            type="button"
            onClick={() => setConfirmOpen(true)}
            disabled={startDisabled}
            className="px-4 py-2 text-[13px] font-semibold bg-red-600 text-white hover:bg-red-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 dark:disabled:bg-slate-600 transition-colors"
          >
            {resumable ? t(k('resume')) : t(k('start'))}
          </button>
        )}
      </div>

      <ModalShell
        isOpen={confirmOpen}
        onClose={() => !startMutation.isPending && setConfirmOpen(false)}
        closeOnBackdrop={false}
        panelClassName="max-w-lg"
        labelledById="raw-reclaim-confirm-title"
      >
        <div className="p-6">
          <h3 id="raw-reclaim-confirm-title" className="text-lg font-semibold text-slate-900 dark:text-white">
            {t(k('confirm.title'))}
          </h3>
          <p className="mt-3 text-sm text-slate-700 dark:text-slate-300">{t(k('confirm.intro'))}</p>
          <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
            <p className="font-medium">{t(k('confirm.removedTitle'))}</p>
            <ul className="mt-1 list-disc space-y-0.5 pl-5">
              <li>{t(k('confirm.removedUser'))}</li>
              <li>{t(k('confirm.removedTimings'))}</li>
              <li>{t(k('confirm.removedAsn'))}</li>
              <li>{t(k('confirm.removedPrefix'))}</li>
            </ul>
          </div>
          <p className="mt-3 text-sm text-slate-700 dark:text-slate-300">{t(k('confirm.kept'))}</p>
          <p className="mt-2 text-sm font-medium text-slate-800 dark:text-slate-200">{t(k('confirm.files'))}</p>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{t(k('confirm.wait'))}</p>

          <label className="mt-4 block text-sm font-medium text-slate-700 dark:text-slate-300" htmlFor="raw-reclaim-max">
            {t(k('confirm.maxChunks'))}
          </label>
          <input
            id="raw-reclaim-max"
            type="number"
            min={1}
            value={maxChunks}
            onChange={(e) => setMaxChunks(e.target.value)}
            placeholder="—"
            className="mt-1 w-32 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t(k('confirm.maxChunksHint'))}</p>

          <div className="mt-6 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setConfirmOpen(false)}
              disabled={startMutation.isPending}
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700 disabled:opacity-50"
            >
              {t('common:buttons.cancel')}
            </button>
            <button
              type="button"
              onClick={confirmStart}
              disabled={startMutation.isPending}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50"
            >
              {startMutation.isPending ? t(k('starting')) : t(k('confirm.confirm'))}
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  );
}

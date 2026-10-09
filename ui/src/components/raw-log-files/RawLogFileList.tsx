import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { viewLogFile, downloadLogFile, deleteLogFile, triggerLogRotation } from '../../api/settings';
import type { LogFileInfo, LogFilesResponse } from '../../types/settings';
import { ModalShell } from '../common/ModalShell';
import { usePermissions } from '../../hooks/usePermissions';
import { formatFileSize, type RawLogMessage } from './shared';

interface RawLogFileListProps {
  data: LogFilesResponse | undefined;
  onRefresh: () => void;
  onMessage: (message: RawLogMessage) => void;
}

const isActiveName = (name: string) => name === 'access_raw.log' || name === 'error_raw.log';

/** Status line, "Rotate now", and the list of raw log files with preview, download and delete. */
export default function RawLogFileList({ data, onRefresh, onMessage }: RawLogFileListProps) {
  const { t, i18n } = useTranslation('logs');
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can('settings:write');
  const [viewingFile, setViewingFile] = useState<string | null>(null);
  const [viewContent, setViewContent] = useState<string>('');
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  const viewFileMutation = useMutation({
    mutationFn: ({ filename, lines }: { filename: string; lines: number }) => viewLogFile(filename, lines),
    onSuccess: (result) => setViewContent(result.content),
  });

  const rotateMutation = useMutation({
    mutationFn: triggerLogRotation,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['logFiles'] });
      // The server answers 200 for three outcomes it does not treat as
      // failures — nothing to cut, a cut that already happened this second,
      // one already running — and names which in `reason`. Reporting all of
      // them as "rotation completed" was the last place #301 stayed invisible:
      // the operator pressed the button, saw success, and the file list did
      // not change. Skips are shown as such, with the reason.
      if (result.status === 'skipped') {
        const reasonKey = result.reason ?? 'unknown';
        onMessage({ type: 'info', text: t([`rawFiles.rotateSkipped.${reasonKey}`, 'rawFiles.rotateSkipped.unknown']) });
      } else {
        onMessage({ type: 'success', text: t('rawFiles.rotateSuccess') });
      }
    },
    onError: (error: Error) => {
      onMessage({ type: 'error', text: t('rawFiles.rotateFail', { error: error.message }) });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteLogFile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['logFiles'] });
      setConfirmDelete(null);
    },
    onError: (error: Error) => {
      setConfirmDelete(null);
      onMessage({ type: 'error', text: error.message });
    },
  });

  const handleViewFile = (filename: string) => {
    setViewingFile(filename);
    viewFileMutation.mutate({ filename, lines: 500 });
  };

  const handleDownloadFile = async (filename: string) => {
    try {
      await downloadLogFile(filename);
    } catch {
      onMessage({ type: 'error', text: t('rawFiles.downloadFailed') });
    }
  };

  const closeViewer = () => {
    setViewingFile(null);
    setViewContent('');
  };

  const files = data?.files ?? [];

  return (
    <>
      {/* Status */}
      <div className={`p-5 rounded-xl transition-colors ${data?.raw_log_enabled ? 'bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800' : 'bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700'
        }`}>
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="font-semibold text-slate-800 dark:text-white">{t('rawFiles.title')}</h3>
            <p className="text-sm mt-1.5">
              {data?.raw_log_enabled ? (
                <span className="text-emerald-700 dark:text-emerald-400">
                  {t('rawFiles.status.enabled', { count: data?.total_count ?? 0, size: formatFileSize(data?.total_size ?? 0) })}
                </span>
              ) : (
                <span className="text-slate-600 dark:text-slate-400">{t('rawFiles.status.disabled')}</span>
              )}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onRefresh}
              className="px-3 py-2 text-sm font-medium bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
              title={t('rawFiles.actions.refresh')}
              aria-label={t('rawFiles.actions.refresh')}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
            {data?.raw_log_enabled && canWrite && (
              <button
                onClick={() => rotateMutation.mutate()}
                disabled={rotateMutation.isPending}
                className="px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                {rotateMutation.isPending ? t('rawFiles.actions.rotating') : t('rawFiles.actions.manualRotate')}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* File list */}
      {files.length > 0 ? (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden transition-colors">
          <div className="px-4 py-3 bg-slate-50 dark:bg-slate-700/50 border-b border-slate-200 dark:border-slate-700">
            <h3 className="font-semibold text-slate-700 dark:text-slate-300 text-sm">{t('rawFiles.list.title')}</h3>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-700">
            {files.map((file: LogFileInfo) => (
              <div key={file.name} className="flex items-center justify-between gap-3 p-4 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                <div className="flex items-center gap-3 min-w-0">
                  <div className={`w-8 h-8 shrink-0 rounded-lg flex items-center justify-center ${file.log_type === 'access' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400' :
                    file.log_type === 'error' ? 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' :
                      'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400'
                    }`}>
                    {file.is_compressed ? (
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="font-medium text-slate-800 dark:text-white text-sm break-all">{file.name}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-2 mt-0.5">
                      <span>{formatFileSize(file.size)}</span>
                      <span>•</span>
                      <span>{new Date(file.modified_at).toLocaleString(i18n.language)}</span>
                      {file.is_compressed && (
                        <>
                          <span>•</span>
                          <span className="text-amber-600 dark:text-amber-400">{t('rawFiles.settings.compressed')}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleViewFile(file.name)}
                    className="p-2 text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded-lg transition-colors"
                    title={t('rawFiles.list.preview')}
                    aria-label={t('rawFiles.list.preview')}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleDownloadFile(file.name)}
                    className="p-2 text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/30 rounded-lg transition-colors"
                    title={t('rawFiles.list.download')}
                    aria-label={t('rawFiles.list.download')}
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                  </button>
                  {canWrite && !isActiveName(file.name) && (
                    <button
                      onClick={() => setConfirmDelete(file.name)}
                      className="p-2 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg transition-colors"
                      title={t('rawFiles.list.delete')}
                      aria-label={t('rawFiles.list.delete')}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-center py-12 bg-slate-50 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
          <svg className="w-12 h-12 text-slate-300 dark:text-slate-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p className="text-slate-500 dark:text-slate-400">{t('rawFiles.list.empty')}</p>
          <p className="text-sm text-slate-400 dark:text-slate-500 mt-1">{t('rawFiles.list.emptyDesc')}</p>
        </div>
      )}

      {/* File viewer */}
      <ModalShell isOpen={!!viewingFile} onClose={closeViewer} panelClassName="max-w-4xl" labelledById="raw-log-view-title">
        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <h3 id="raw-log-view-title" className="font-semibold text-slate-800 dark:text-white break-all">{viewingFile}</h3>
          <button
            onClick={closeViewer}
            aria-label={t('common:buttons.close')}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-4">
          {viewFileMutation.isPending ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all bg-slate-50 dark:bg-slate-900 p-4 rounded-lg">
              {viewContent || t('rawFiles.modal.noContent')}
            </pre>
          )}
        </div>
        <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-700 flex justify-end gap-2">
          <button
            onClick={() => viewingFile && handleDownloadFile(viewingFile)}
            className="px-4 py-2 text-sm font-medium bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors"
          >
            {t('rawFiles.list.download')}
          </button>
          <button
            onClick={closeViewer}
            className="px-4 py-2 text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
          >
            {t('rawFiles.modal.close')}
          </button>
        </div>
      </ModalShell>

      {/* Delete confirmation */}
      <ModalShell isOpen={!!confirmDelete} onClose={() => setConfirmDelete(null)} panelClassName="max-w-md" labelledById="raw-log-delete-title">
        <div className="p-6">
          <h3 id="raw-log-delete-title" className="text-lg font-semibold text-slate-800 dark:text-white mb-2">{t('rawFiles.modal.deleteTitle')}</h3>
          <p className="text-sm text-slate-600 dark:text-slate-400 mb-4 break-all">
            {t('rawFiles.modal.deleteConfirm', { file: confirmDelete })}
            <br />{t('rawFiles.modal.irreversible')}
          </p>
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setConfirmDelete(null)}
              className="px-4 py-2 text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
            >
              {t('rawFiles.modal.cancel')}
            </button>
            <button
              onClick={() => confirmDelete && deleteMutation.mutate(confirmDelete)}
              disabled={deleteMutation.isPending}
              className="px-4 py-2 text-sm font-medium bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
            >
              {deleteMutation.isPending ? t('rawFiles.modal.deleting') : t('rawFiles.modal.delete')}
            </button>
          </div>
        </div>
      </ModalShell>
    </>
  );
}

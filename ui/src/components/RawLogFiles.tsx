import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getSystemSettings,
  updateSystemSettings,
  getLogFiles,
  viewLogFile,
  downloadLogFile,
  deleteLogFile,
  triggerLogRotation,
} from '../api/settings';
import type { LogFileInfo, UpdateSystemSettingsRequest, SystemSettings } from '../types/settings';

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export default function RawLogFiles() {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const [viewingFile, setViewingFile] = useState<string | null>(null);
  const [viewContent, setViewContent] = useState<string>('');
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [editedSettings, setEditedSettings] = useState<UpdateSystemSettingsRequest>({});
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Fetch settings
  const { data: settings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  // Fetch log files
  const { data: logFilesData, refetch: refetchLogFiles } = useQuery({
    queryKey: ['logFiles'],
    queryFn: getLogFiles,
  });

  // Update settings mutation
  const updateMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      queryClient.invalidateQueries({ queryKey: ['logFiles'] });
      setEditedSettings({});
      setEditedSettings({});
      setSaveMessage({ type: 'success', text: t('rawFiles.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 5000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: t('rawFiles.saveFail', { error: error.message }) });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  // View file mutation
  const viewFileMutation = useMutation({
    mutationFn: ({ filename, lines }: { filename: string; lines: number }) =>
      viewLogFile(filename, lines),
    onSuccess: (data) => {
      setViewContent(data.content);
    },
  });

  // Rotate logs mutation
  const rotateMutation = useMutation({
    mutationFn: triggerLogRotation,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['logFiles'] });
      setSaveMessage({ type: 'success', text: t('rawFiles.rotateSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
  });

  // Delete file mutation
  const deleteMutation = useMutation({
    mutationFn: deleteLogFile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['logFiles'] });
      setConfirmDelete(null);
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
      setSaveMessage({
        type: 'error',
        text: t('rawLogs.downloadFailed') || 'Download failed'
      });
      setTimeout(() => setSaveMessage(null), 5000);
    }
  };

  const handleChange = (key: keyof UpdateSystemSettingsRequest, value: string | number | boolean | object) => {
    setEditedSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (Object.keys(editedSettings).length > 0) {
      updateMutation.mutate(editedSettings);
    }
  };

  const getValue = <K extends keyof SystemSettings>(key: K): SystemSettings[K] | undefined => {
    if (key in editedSettings) {
      return (editedSettings as Partial<SystemSettings>)[key] as SystemSettings[K];
    }
    return settings?.[key];
  };

  const isModified = Object.keys(editedSettings).length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-slate-200">{t('rawFiles.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('rawFiles.subtitle')}
          </p>
        </div>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'
          }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Raw Log Settings */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('rawFiles.settings.title')}</h3>
          </div>
          <button
            onClick={handleSave}
            disabled={!isModified || updateMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 transition-colors"
          >
            {updateMutation.isPending ? t('rawFiles.settings.saving') : t('rawFiles.settings.save')}
          </button>
        </div>

        {/* Enable Raw Log */}
        <div className="space-y-4">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={getValue('raw_log_enabled') ?? false}
              onChange={(e) => handleChange('raw_log_enabled', e.target.checked)}
              className="w-5 h-5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700"
            />
            <div>
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{t('rawFiles.settings.enable')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{t('rawFiles.settings.enableDesc')}</p>
            </div>
          </label>

          {getValue('raw_log_enabled') && (
            <div className="ml-8 space-y-4 border-l-2 border-slate-200 dark:border-slate-700 pl-4">
              {/* Max Size */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('rawFiles.settings.maxSize')}
                </label>
                <input
                  type="number"
                  min="10"
                  max="1000"
                  value={getValue('raw_log_max_size_mb') ?? 100}
                  onChange={(e) => handleChange('raw_log_max_size_mb', parseInt(e.target.value))}
                  className="w-32 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                />
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('rawFiles.settings.maxSizeDesc')}</p>
              </div>

              {/* Rotate Count */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('rawFiles.settings.rotateCount')}
                </label>
                <input
                  type="number"
                  min="1"
                  max="30"
                  value={getValue('raw_log_rotate_count') ?? 5}
                  onChange={(e) => handleChange('raw_log_rotate_count', parseInt(e.target.value))}
                  className="w-32 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                />
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('rawFiles.settings.rotateCountDesc')}</p>
              </div>

              {/* Retention Days */}
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                  {t('rawFiles.settings.retention')}
                </label>
                <input
                  type="number"
                  min="1"
                  max="365"
                  value={getValue('raw_log_retention_days') ?? 7}
                  onChange={(e) => handleChange('raw_log_retention_days', parseInt(e.target.value))}
                  className="w-32 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                />
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('rawFiles.settings.retentionDesc')}</p>
              </div>

              {/* Compress */}
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={getValue('raw_log_compress_rotated') ?? true}
                  onChange={(e) => handleChange('raw_log_compress_rotated', e.target.checked)}
                  className="w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700"
                />
                <div>
                  <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('rawFiles.settings.compress')}</span>
                  <p className="text-xs text-slate-500 dark:text-slate-400">{t('rawFiles.settings.compressDesc')}</p>
                </div>
              </label>

              {/* Estimated Size */}
              <div className="bg-slate-50 dark:bg-slate-700/50 rounded-lg p-3 text-sm">
                <span className="text-slate-600 dark:text-slate-400">{t('rawFiles.settings.estimatedSize')}: </span>
                <span className="font-semibold text-slate-800 dark:text-slate-200">
                  {((getValue('raw_log_max_size_mb') ?? 100) * (getValue('raw_log_rotate_count') ?? 5) * 2 * (getValue('raw_log_compress_rotated') ? 0.1 : 1)).toFixed(0)} MB
                </span>
                {getValue('raw_log_compress_rotated') && <span className="text-slate-500 dark:text-slate-400"> ({t('rawFiles.settings.compressed')})</span>}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Status & File List */}
      <div className={`p-5 rounded-xl transition-colors ${logFilesData?.raw_log_enabled ? 'bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800' : 'bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700'
        }`}>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-slate-800 dark:text-white">{t('rawFiles.title')}</h3>
            <p className="text-sm mt-1.5">
              {logFilesData?.raw_log_enabled ? (
                <span className="text-emerald-700 dark:text-emerald-400">
                  {t('rawFiles.status.enabled', { count: logFilesData?.total_count ?? 0, size: formatFileSize(logFilesData?.total_size ?? 0) })}
                </span>
              ) : (
                <span className="text-slate-600 dark:text-slate-400">
                  {t('rawFiles.status.disabled')}
                </span>
              )}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => refetchLogFiles()}
              className="px-3 py-2 text-sm font-medium bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
              title="새로고침"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
            {logFilesData?.raw_log_enabled && (
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

      {/* File List */}
      {(logFilesData?.files?.length ?? 0) > 0 ? (
        <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden transition-colors">
          <div className="px-4 py-3 bg-slate-50 dark:bg-slate-700/50 border-b border-slate-200 dark:border-slate-700">
            <h3 className="font-semibold text-slate-700 dark:text-slate-300 text-sm">{t('rawFiles.list.title')}</h3>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-700">
            {logFilesData?.files.map((file: LogFileInfo) => (
              <div key={file.name} className="flex items-center justify-between p-4 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${file.log_type === 'access' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400' :
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
                  <div>
                    <div className="font-medium text-slate-800 dark:text-white text-sm">{file.name}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2 mt-0.5">
                      <span>{formatFileSize(file.size)}</span>
                      <span>•</span>
                      <span>{new Date(file.modified_at).toLocaleString('ko-KR')}</span>
                      {file.is_compressed && (
                        <>
                          <span>•</span>
                          <span className="text-amber-600 dark:text-amber-400">{t('rawFiles.settings.compressed')}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleViewFile(file.name)}
                    className="p-2 text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded-lg transition-colors"
                    title={t('rawFiles.list.preview')}
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
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                    </svg>
                  </button>
                  {file.name !== 'access.log' && file.name !== 'error.log' &&
                    file.name !== 'access_raw.log' && file.name !== 'error_raw.log' && (
                      <button
                        onClick={() => setConfirmDelete(file.name)}
                        className="p-2 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg transition-colors"
                        title={t('rawFiles.list.delete')}
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
          <p className="text-sm text-slate-400 dark:text-slate-500 mt-1">
            {t('rawFiles.list.emptyDesc')}
          </p>
        </div>
      )}

      {/* File Viewer Modal */}
      {viewingFile && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[80vh] flex flex-col transition-colors">
            <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
              <h3 className="font-semibold text-slate-800 dark:text-white">{viewingFile}</h3>
              <button
                onClick={() => {
                  setViewingFile(null);
                  setViewContent('');
                }}
                className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              {viewFileMutation.isPending ? (
                <div className="flex items-center justify-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
              ) : (
                <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all bg-slate-50 dark:bg-slate-900 p-4 rounded-lg">
                  {viewContent || 'No content'}
                </pre>
              )}
            </div>
            <div className="px-5 py-3 border-t border-slate-200 dark:border-slate-700 flex justify-end gap-2">
              <button
                onClick={() => handleDownloadFile(viewingFile)}
                className="px-4 py-2 text-sm font-medium bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors"
              >
                {t('rawFiles.list.download')}
              </button>
              <button
                onClick={() => {
                  setViewingFile(null);
                  setViewContent('');
                }}
                className="px-4 py-2 text-sm font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
              >
                {t('rawFiles.modal.close')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-md p-6 transition-colors">
            <h3 className="text-lg font-semibold text-slate-800 dark:text-white mb-2">{t('rawFiles.modal.deleteTitle')}</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
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
                onClick={() => deleteMutation.mutate(confirmDelete)}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 text-sm font-medium bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
              >
                {deleteMutation.isPending ? t('rawFiles.modal.deleting') : t('rawFiles.modal.delete')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

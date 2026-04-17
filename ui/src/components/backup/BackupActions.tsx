import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { CreateBackupRequest } from '../../types/settings';
import { formatBytes } from './BackupList';

interface CreateBackupModalProps {
  newBackup: CreateBackupRequest;
  setNewBackup: React.Dispatch<React.SetStateAction<CreateBackupRequest>>;
  isPending: boolean;
  onCreate: () => void;
  onClose: () => void;
}

export function CreateBackupModal({ newBackup, setNewBackup, isPending, onCreate, onClose }: CreateBackupModalProps) {
  const { t } = useTranslation('settings');

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md p-6 transition-colors">
        <h2 className="text-xl font-bold mb-4 dark:text-white">{t('backupManager.createModal.title')}</h2>

        <div className="space-y-4">
          <div className="space-y-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={newBackup.includes_config}
                onChange={(e) => setNewBackup({ ...newBackup, includes_config: e.target.checked })}
                className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
              />
              <span className="dark:text-gray-300">{t('backupManager.createModal.includeConfig')}</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={newBackup.includes_certificates}
                onChange={(e) => setNewBackup({ ...newBackup, includes_certificates: e.target.checked })}
                className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
              />
              <span className="dark:text-gray-300">{t('backupManager.createModal.includeCerts')}</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={newBackup.includes_database}
                onChange={(e) => setNewBackup({ ...newBackup, includes_database: e.target.checked })}
                className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 dark:bg-slate-700"
              />
              <span className="dark:text-gray-300">{t('backupManager.createModal.includeDatabase')}</span>
            </label>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('backupManager.createModal.description')}</label>
            <input
              type="text"
              value={newBackup.description || ''}
              onChange={(e) => setNewBackup({ ...newBackup, description: e.target.value })}
              placeholder={t('backupManager.createModal.descriptionPlaceholder')}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-slate-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            {t('backupManager.buttons.cancel')}
          </button>
          <button
            onClick={onCreate}
            disabled={isPending}
            className="px-4 py-2 bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50"
          >
            {isPending ? t('backupManager.buttons.creating') : t('backupManager.createBackup')}
          </button>
        </div>
      </div>
    </div>
  );
}

interface UploadRestoreModalProps {
  uploadFile: File | null;
  onFileSelect: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onUploadRestore: () => void;
  onClose: () => void;
  isPending: boolean;
}

export function UploadRestoreModal({
  uploadFile,
  onFileSelect,
  onUploadRestore,
  onClose,
  isPending,
}: UploadRestoreModalProps) {
  const { t } = useTranslation('settings');
  const fileInputRef = useRef<HTMLInputElement>(null);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md p-6 transition-colors">
        <h2 className="text-xl font-bold mb-4 dark:text-white">{t('backupManager.uploadModal.title')}</h2>

        <div className="space-y-4">
          <div className="text-sm text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/30 p-3 rounded-lg border border-amber-200 dark:border-amber-800">
            {t('backupManager.uploadModal.warning')}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">{t('backupManager.uploadModal.selectFile')}</label>
            <input
              ref={fileInputRef}
              type="file"
              accept=".tar.gz"
              onChange={onFileSelect}
              className="hidden"
            />
            <div
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 dark:hover:border-blue-400 transition-colors"
            >
              {uploadFile ? (
                <div>
                  <p className="text-gray-800 dark:text-white font-medium">{uploadFile.name}</p>
                  <p className="text-sm text-gray-500 dark:text-gray-400">{formatBytes(uploadFile.size)}</p>
                </div>
              ) : (
                <div>
                  <p className="text-gray-500 dark:text-gray-400">{t('backupManager.uploadModal.clickToSelect')}</p>
                  <p className="text-sm text-gray-400 dark:text-gray-500 mt-1">{t('backupManager.uploadModal.dragAndDrop')}</p>
                </div>
              )}
            </div>
          </div>

          <div className="text-sm text-gray-500 dark:text-gray-400">
            <p className="font-medium mb-1 dark:text-gray-300">{t('backupManager.uploadModal.restoreInfo')}</p>
            <ul className="list-disc list-inside space-y-0.5">
              <li>{t('backupManager.uploadModal.items.proxyHosts')}</li>
              <li>{t('backupManager.uploadModal.items.redirectHosts')}</li>
              <li>{t('backupManager.uploadModal.items.accessLists')}</li>
              <li>{t('backupManager.uploadModal.items.certificates')}</li>
              <li>{t('backupManager.uploadModal.items.wafConfig')}</li>
              <li>{t('backupManager.uploadModal.items.globalSettings')}</li>
            </ul>
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            {t('backupManager.buttons.cancel')}
          </button>
          <button
            onClick={onUploadRestore}
            disabled={!uploadFile || isPending}
            className="px-4 py-2 bg-green-600 text-white hover:bg-green-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isPending ? t('backupManager.buttons.restoring') : t('backupManager.uploadRestore')}
          </button>
        </div>
      </div>
    </div>
  );
}

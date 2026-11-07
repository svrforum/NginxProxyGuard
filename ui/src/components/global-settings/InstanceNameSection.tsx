import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getSystemSettings, updateSystemSettings } from '../../api/settings';
import { usePermissions } from '../../hooks/usePermissions';

const MAX_LENGTH = 32;

/**
 * The instance name (#369), shown in the header and the browser tab to tell
 * several NPG installs apart. Like ErrorPageLanguageSection it lives in
 * system_settings, so it reads and saves on its own.
 */
export default function InstanceNameSection() {
  const { t } = useTranslation('settings');
  // Hiding is a convenience; the API refuses the save without settings:write.
  const canWrite = usePermissions().can('settings:write');
  const queryClient = useQueryClient();
  const [editedValue, setEditedValue] = useState<string | null>(null);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const savedValue = systemSettings?.instance_name ?? '';
  const currentValue = editedValue ?? savedValue;
  const isModified = editedValue !== null && editedValue.trim() !== savedValue;

  const saveMutation = useMutation({
    mutationFn: (name: string) => updateSystemSettings({ instance_name: name }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      queryClient.invalidateQueries({ queryKey: ['instance'] });
      setEditedValue(null);
      setSaveMessage({ type: 'success', text: t('messages.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (err: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${err.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  return (
    <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
      <h3 className="text-base font-semibold text-slate-800 dark:text-white mb-2">
        {t('global.advanced.instanceName.title')}
      </h3>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
        {t('global.advanced.instanceName.description')}
      </p>
      <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label htmlFor="instance-name" className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              {t('global.advanced.instanceName.label')}
            </label>
            <input
              id="instance-name"
              type="text"
              value={currentValue}
              maxLength={MAX_LENGTH}
              placeholder={t('global.advanced.instanceName.placeholder')}
              onChange={(e) => setEditedValue(e.target.value)}
              disabled={!canWrite || saveMutation.isPending}
              className="w-full px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50"
            />
          </div>
          {canWrite && <button
            onClick={() => editedValue !== null && saveMutation.mutate(editedValue.trim())}
            disabled={!isModified || saveMutation.isPending}
            className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {saveMutation.isPending ? t('global.buttons.saving') : t('global.buttons.save')}
          </button>}
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
          {t('global.advanced.instanceName.help', { max: MAX_LENGTH })}
        </p>
        {saveMessage && (
          <div
            className={`mt-3 px-3 py-2 rounded-lg text-xs font-medium ${
              saveMessage.type === 'success'
                ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800'
                : 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'
            }`}
          >
            {saveMessage.text}
          </div>
        )}
      </div>
    </div>
  );
}

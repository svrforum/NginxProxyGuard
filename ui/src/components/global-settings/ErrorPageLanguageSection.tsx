import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getSystemSettings, updateSystemSettings } from '../../api/settings';

const ERROR_PAGE_LANGUAGE_OPTIONS = [
  { value: 'auto', label: 'Auto (browser language)', labelKo: '자동 (브라우저 언어)' },
  { value: 'ko', label: '한국어', labelKo: '한국어' },
  { value: 'en', label: 'English', labelKo: 'English' },
];

/**
 * Self-contained section that renders inside the Global Settings > Advanced tab.
 *
 * The underlying column (`ui_error_page_language`) lives in the `system_settings`
 * table, not `global_settings`, so the parent tab's data accessors cannot reach
 * it. This component owns its own React Query cache key (`systemSettings`) and
 * a separate save button to keep the read/write flow decoupled from the main
 * Global Settings form.
 */
export default function ErrorPageLanguageSection() {
  const { t, i18n } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [editedValue, setEditedValue] = useState<string | null>(null);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: systemSettings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const currentValue = editedValue ?? systemSettings?.ui_error_page_language ?? 'auto';
  const isModified = editedValue !== null && editedValue !== (systemSettings?.ui_error_page_language ?? 'auto');

  // Reset local edit when the underlying fetched value changes (e.g. after save invalidates the query)
  useEffect(() => {
    if (systemSettings?.ui_error_page_language !== undefined && editedValue === null) {
      setEditedValue(null); // keep it at null; we render currentValue from the fetched value directly
    }
  }, [systemSettings?.ui_error_page_language, editedValue]);

  const saveMutation = useMutation({
    mutationFn: (lang: string) => updateSystemSettings({ ui_error_page_language: lang }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      setEditedValue(null);
      setSaveMessage({ type: 'success', text: t('messages.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (err: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${err.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  const handleSave = () => {
    if (editedValue !== null) {
      saveMutation.mutate(editedValue);
    }
  };

  return (
    <div className="border-t border-slate-200 dark:border-slate-700 pt-6">
      <div className="flex items-center gap-2 mb-4">
        <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129" />
        </svg>
        <h3 className="text-base font-semibold text-slate-800 dark:text-white">
          {t('global.advanced.errorPageLanguage.title')}
        </h3>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
        {t('global.advanced.errorPageLanguage.description')}
      </p>
      <div className="bg-slate-50 dark:bg-slate-700/30 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              {t('global.advanced.errorPageLanguage.label')}
            </label>
            <select
              value={currentValue}
              onChange={(e) => setEditedValue(e.target.value)}
              disabled={saveMutation.isPending}
              className="w-full px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50"
            >
              {ERROR_PAGE_LANGUAGE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {i18n.language === 'ko' ? opt.labelKo : opt.label}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={handleSave}
            disabled={!isModified || saveMutation.isPending}
            className="px-4 py-2 text-sm font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {saveMutation.isPending ? t('global.buttons.saving') : t('global.buttons.save')}
          </button>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
          {t('global.advanced.errorPageLanguage.help')}
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

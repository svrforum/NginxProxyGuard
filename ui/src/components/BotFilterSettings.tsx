import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { HelpTip } from './common/HelpTip';
import { getSystemSettings, updateSystemSettings } from '../api/settings';
import type { UpdateSystemSettingsRequest } from '../types/settings';

export default function BotFilterSettings() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [editedSettings, setEditedSettings] = useState<UpdateSystemSettingsRequest>({});
  const [expandedList, setExpandedList] = useState<'bad' | 'ai' | 'search' | 'suspicious' | null>(null);

  const { data: settings, isLoading } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const updateMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      setEditedSettings({});
    },
  });

  const handleChange = (key: keyof UpdateSystemSettingsRequest, value: string) => {
    setEditedSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (Object.keys(editedSettings).length > 0) {
      updateMutation.mutate(editedSettings);
    }
  };

  const hasChanges = Object.keys(editedSettings).length > 0;

  const toggleList = (list: 'bad' | 'ai' | 'search' | 'suspicious') => {
    setExpandedList(expandedList === list ? null : list);
  };

  const getListCount = (list: string | undefined) => {
    if (!list) return 0;
    return list.split('\n').filter(l => l.trim()).length;
  };

  const getListValue = (key: 'bot_list_bad_bots' | 'bot_list_ai_bots' | 'bot_list_search_engines' | 'bot_list_suspicious_clients') => {
    return (editedSettings as Record<string, string>)[key] ?? settings?.[key] ?? '';
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <svg className="animate-spin w-8 h-8 text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Save Button */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-800 dark:text-white">{t('system.botfilter.lists.title')}</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('system.botfilter.lists.description')}</p>
        </div>
        {hasChanges && (
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 text-sm font-medium flex items-center gap-2"
          >
            {updateMutation.isPending ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                {t('system.buttons.saving')}
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                {t('system.buttons.save')}
              </>
            )}
          </button>
        )}
      </div>

      {/* Info Banner */}
      <div className="p-4 bg-blue-50 dark:bg-blue-900/10 rounded-xl border border-blue-200 dark:border-blue-800 transition-colors">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <p className="text-sm text-blue-800 dark:text-blue-300 font-medium flex items-center gap-2">
              {t('system.botfilter.defaults.title')}
              <HelpTip contentKey="help.botfilter.defaults" ns="settings" />
            </p>
            <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">
              {t('system.botfilter.defaults.description')}
            </p>
          </div>
        </div>
      </div>

      {/* Bot Lists */}
      <div className="space-y-3">
        {/* Bad Bots - Red */}
        <div className="rounded-xl border border-red-200 dark:border-red-800 overflow-hidden transition-colors">
          <div
            className="py-3 px-4 bg-red-50 dark:bg-red-900/10 flex items-center justify-between cursor-pointer hover:bg-red-100 dark:hover:bg-red-900/20 transition-colors"
            onClick={() => toggleList('bad')}
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-100 dark:bg-red-900/30 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              </div>
              <div>
                <span className="text-sm font-semibold text-red-800 dark:text-red-300 flex items-center gap-2">
                  {t('system.botfilter.lists.badBots.label')}
                  <HelpTip contentKey="help.botfilter.badBots" ns="settings" />
                </span>
                <p className="text-xs text-red-600 dark:text-red-400">{t('system.botfilter.lists.badBots.description')}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 text-xs font-medium rounded-full">
                {t('system.botfilter.lists.patternCount', { count: getListCount(getListValue('bot_list_bad_bots')) })}
              </span>
              <svg className={`w-5 h-5 text-red-600 transition-transform ${expandedList === 'bad' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>
          {expandedList === 'bad' && (
            <div className="p-4 bg-white dark:bg-slate-800 border-t border-red-200 dark:border-red-800 transition-colors">
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('system.botfilter.customAgents.description')}</p>
              <textarea
                value={getListValue('bot_list_bad_bots')}
                onChange={(e) => handleChange('bot_list_bad_bots', e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-700 dark:text-slate-300 font-mono placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 transition-colors"
                rows={10}
                placeholder={t('system.botfilter.lists.badBots.placeholder')}
              />
            </div>
          )}
        </div>

        {/* AI Bots - Purple */}
        <div className="rounded-xl border border-purple-200 dark:border-purple-800 overflow-hidden transition-colors">
          <div
            className="py-3 px-4 bg-purple-50 dark:bg-purple-900/10 flex items-center justify-between cursor-pointer hover:bg-purple-100 dark:hover:bg-purple-900/20 transition-colors"
            onClick={() => toggleList('ai')}
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <div>
                <span className="text-sm font-semibold text-purple-800 dark:text-purple-300 flex items-center gap-2">
                  {t('system.botfilter.lists.aiBots.label')}
                  <HelpTip contentKey="help.botfilter.aiBots" ns="settings" />
                </span>
                <p className="text-xs text-purple-600 dark:text-purple-400">{t('system.botfilter.lists.aiBots.description')}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 text-xs font-medium rounded-full">
                {t('system.botfilter.lists.patternCount', { count: getListCount(getListValue('bot_list_ai_bots')) })}
              </span>
              <svg className={`w-5 h-5 text-purple-600 transition-transform ${expandedList === 'ai' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>
          {expandedList === 'ai' && (
            <div className="p-4 bg-white dark:bg-slate-800 border-t border-purple-200 dark:border-purple-800 transition-colors">
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('system.botfilter.customAgents.description')}</p>
              <textarea
                value={getListValue('bot_list_ai_bots')}
                onChange={(e) => handleChange('bot_list_ai_bots', e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-700 dark:text-slate-300 font-mono placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500 transition-colors"
                rows={10}
                placeholder={t('system.botfilter.lists.aiBots.placeholder')}
              />
            </div>
          )}
        </div>

        {/* Search Engines - Green */}
        <div className="rounded-xl border border-emerald-200 dark:border-emerald-800 overflow-hidden transition-colors">
          <div
            className="py-3 px-4 bg-emerald-50 dark:bg-emerald-900/10 flex items-center justify-between cursor-pointer hover:bg-emerald-100 dark:hover:bg-emerald-900/20 transition-colors"
            onClick={() => toggleList('search')}
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-emerald-100 dark:bg-emerald-900/30 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <div>
                <span className="text-sm font-semibold text-emerald-800 dark:text-emerald-300 flex items-center gap-2">
                  {t('system.botfilter.lists.searchEngines.label')}
                  <HelpTip contentKey="help.botfilter.searchEngines" ns="settings" />
                </span>
                <p className="text-xs text-emerald-600 dark:text-emerald-400">{t('system.botfilter.lists.searchEngines.description')}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="px-2 py-1 bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 text-xs font-medium rounded-full">
                {t('system.botfilter.lists.patternCount', { count: getListCount(getListValue('bot_list_search_engines')) })}
              </span>
              <svg className={`w-5 h-5 text-emerald-600 transition-transform ${expandedList === 'search' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>
          {expandedList === 'search' && (
            <div className="p-4 bg-white dark:bg-slate-800 border-t border-emerald-200 dark:border-emerald-800 transition-colors">
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('system.botfilter.options.allowSearchEngines.description')}</p>
              <textarea
                value={getListValue('bot_list_search_engines')}
                onChange={(e) => handleChange('bot_list_search_engines', e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-700 dark:text-slate-300 font-mono placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-emerald-500 transition-colors"
                rows={10}
                placeholder={t('system.botfilter.lists.searchEngines.placeholder')}
              />
            </div>
          )}
        </div>

        {/* Suspicious Clients - Orange */}
        <div className="rounded-xl border border-orange-200 dark:border-orange-800 overflow-hidden transition-colors">
          <div
            className="py-3 px-4 bg-orange-50 dark:bg-orange-900/10 flex items-center justify-between cursor-pointer hover:bg-orange-100 dark:hover:bg-orange-900/20 transition-colors"
            onClick={() => toggleList('suspicious')}
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-orange-100 dark:bg-orange-900/30 rounded-lg flex items-center justify-center">
                <svg className="w-5 h-5 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <span className="text-sm font-semibold text-orange-800 dark:text-orange-300 flex items-center gap-2">
                  {t('system.botfilter.options.challengeSuspicious.label')}
                  <HelpTip contentKey="help.botfilter.suspicious" ns="settings" />
                </span>
                <p className="text-xs text-orange-600 dark:text-orange-400">{t('system.botfilter.options.challengeSuspicious.description')}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 text-xs font-medium rounded-full">
                {t('system.botfilter.lists.patternCount', { count: getListCount(getListValue('bot_list_suspicious_clients')) })}
              </span>
              <svg className={`w-5 h-5 text-orange-600 transition-transform ${expandedList === 'suspicious' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>
          {expandedList === 'suspicious' && (
            <div className="p-4 bg-white dark:bg-slate-800 border-t border-orange-200 dark:border-orange-800 transition-colors">
              <div className="p-3 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-lg mb-3">
                <p className="text-xs text-amber-700 dark:text-amber-400">
                  <strong>{t('common:status.warning')}:</strong> {t('system.botfilter.options.challengeSuspicious.description')}
                </p>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{t('system.botfilter.customAgents.description')}</p>
              <textarea
                value={getListValue('bot_list_suspicious_clients')}
                onChange={(e) => handleChange('bot_list_suspicious_clients', e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-700 dark:text-slate-300 font-mono placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-orange-500 transition-colors"
                rows={10}
                placeholder={t('system.botfilter.lists.suspicious.placeholder')}
              />
            </div>
          )}
        </div>
      </div>

      {/* Bottom Save Button (visible when there are changes) */}
      {hasChanges && (
        <div className="flex justify-end pt-4 border-t border-slate-200 dark:border-slate-700">
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="px-6 py-2.5 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 text-sm font-medium flex items-center gap-2"
          >
            {updateMutation.isPending ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                {t('system.buttons.saving')}
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                {t('system.buttons.save')}
              </>
            )}
          </button>
        </div>
      )}

      {/* Success Message */}
      {updateMutation.isSuccess && !hasChanges && (
        <div className="p-4 bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800 rounded-lg flex items-center gap-3">
          <svg className="w-5 h-5 text-emerald-600 dark:text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-sm text-emerald-700 dark:text-emerald-400 font-medium">{t('common:messages.saveSuccess')}</span>
        </div>
      )}

      {/* Error Message */}
      {updateMutation.isError && (
        <div className="p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg flex items-center gap-3">
          <svg className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-sm text-red-700 dark:text-red-400 font-medium">{t('common:messages.saveFailed')}</span>
        </div>
      )}
    </div>
  );
}

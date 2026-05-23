import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getGlobalSettings,
  updateGlobalSettings,
  resetGlobalSettings,
  applySettingsPreset,
} from '../api/settings';
import type { GlobalSettings as GlobalSettingsType } from '../types/settings';
import type { TabType } from './global-settings/types';
import WorkerTab from './global-settings/WorkerTab';
import HttpTab from './global-settings/HttpTab';
import PerformanceTab from './global-settings/PerformanceTab';
import CompressionTab from './global-settings/CompressionTab';
import SSLTab from './global-settings/SSLTab';
import TimeoutTab from './global-settings/TimeoutTab';
import AdvancedTab from './global-settings/AdvancedTab';

export default function GlobalSettings() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('worker');
  const [editedSettings, setEditedSettings] = useState<Partial<GlobalSettingsType>>({});

  const { data: settings, isLoading } = useQuery({
    queryKey: ['globalSettings'],
    queryFn: getGlobalSettings,
  });

  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const updateMutation = useMutation({
    mutationFn: updateGlobalSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['globalSettings'] });
      setEditedSettings({});
      setSaveMessage({ type: 'success', text: t('messages.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${error.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  const resetMutation = useMutation({
    mutationFn: resetGlobalSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['globalSettings'] });
    },
  });

  const presetMutation = useMutation({
    mutationFn: applySettingsPreset,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['globalSettings'] });
      setEditedSettings({});
      setSaveMessage({ type: 'success', text: t('global.preset.applied', { defaultValue: '권장 설정이 적용되었습니다.' }) });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: `${t('global.preset.failed', { defaultValue: '권장 설정 적용 실패' })}: ${error.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  const handleApplyPerformancePreset = () => {
    if (confirm(t('global.preset.confirmPerformance', {
      defaultValue: 'Performance 권장 설정을 적용하시겠습니까? 현재 값이 모두 권장값으로 덮어쓰여지며, nginx가 즉시 reload됩니다.',
    }))) {
      presetMutation.mutate('performance');
    }
  };

  const handleChange = (key: keyof GlobalSettingsType, value: string | number | boolean) => {
    setEditedSettings((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (Object.keys(editedSettings).length > 0) {
      updateMutation.mutate(editedSettings);
    }
  };

  const getValue = (key: keyof GlobalSettingsType): string | number | boolean | undefined => {
    return editedSettings[key] !== undefined ? editedSettings[key] : settings?.[key];
  };

  const getNumberValue = (key: keyof GlobalSettingsType, defaultValue: number = 0): number => {
    const val = getValue(key);
    return typeof val === 'number' ? val : defaultValue;
  };

  const getStringValue = (key: keyof GlobalSettingsType, defaultValue: string = ''): string => {
    const val = getValue(key);
    return typeof val === 'string' ? val : defaultValue;
  };

  const getBoolValue = (key: keyof GlobalSettingsType): boolean => {
    const val = getValue(key);
    return typeof val === 'boolean' ? val : false;
  };

  const isModified = Object.keys(editedSettings).length > 0;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const tabContentProps = { getValue, getNumberValue, getStringValue, getBoolValue, handleChange };

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'worker', label: t('global.tabs.worker'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" /></svg> },
    { id: 'http', label: t('global.tabs.http'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg> },
    { id: 'performance', label: t('global.tabs.performance'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg> },
    { id: 'compression', label: t('global.tabs.compression'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" /></svg> },
    { id: 'ssl', label: t('global.tabs.ssl'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg> },
    { id: 'timeout', label: t('global.tabs.timeout'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> },
    { id: 'advanced', label: t('global.tabs.advanced'), icon: <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg> },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-white">{t('global.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('global.description')}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleApplyPerformancePreset}
            disabled={presetMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-emerald-600 text-white hover:bg-emerald-700 rounded-lg disabled:opacity-50 transition-colors"
            title={t('global.preset.tooltipPerformance', { defaultValue: 'nginx 권장 튜닝값으로 일괄 적용' })}
          >
            {presetMutation.isPending
              ? t('global.preset.applying', { defaultValue: '적용 중...' })
              : t('global.preset.applyPerformance', { defaultValue: '권장 설정 적용' })}
          </button>
          <button
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-white rounded-lg disabled:opacity-50 transition-colors"
          >
            {t('global.buttons.reset')}
          </button>
          <button
            onClick={handleSave}
            disabled={!isModified || updateMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 dark:disabled:bg-slate-700 dark:disabled:text-slate-500 transition-colors"
          >
            {updateMutation.isPending ? t('global.buttons.saving') : t('global.buttons.save')}
          </button>
        </div>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-900/30'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/30'
          }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Tabs */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700">
        <div className="border-b border-slate-200 dark:border-slate-700 px-2">
          <div className="flex overflow-x-auto gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-[13px] font-semibold whitespace-nowrap border-b-2 transition-all ${activeTab === tab.id
                  ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                  }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6">
          {activeTab === 'worker' && <WorkerTab {...tabContentProps} />}
          {activeTab === 'http' && <HttpTab {...tabContentProps} />}
          {activeTab === 'performance' && <PerformanceTab {...tabContentProps} />}
          {activeTab === 'compression' && <CompressionTab {...tabContentProps} />}
          {activeTab === 'ssl' && <SSLTab {...tabContentProps} />}
          {activeTab === 'timeout' && <TimeoutTab {...tabContentProps} />}
          {activeTab === 'advanced' && <AdvancedTab {...tabContentProps} />}
        </div>
      </div>
    </div>
  );
}

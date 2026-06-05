import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
    getSystemLogConfig,
    updateSystemLogConfig,
} from '../api/settings';
import type { SystemLogConfig } from '../types/settings';
import { HelpTip } from './common/HelpTip';

export default function SystemLogSettings() {
    const queryClient = useQueryClient();
    const { t } = useTranslation('settings');
    const [editedLogConfig, setEditedLogConfig] = useState<Partial<SystemLogConfig>>({});
    const [excludePatternsText, setExcludePatternsText] = useState<string | null>(null);
    const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const { data: systemLogConfig, isLoading } = useQuery({
        queryKey: ['systemLogConfig'],
        queryFn: getSystemLogConfig,
    });

    const updateLogConfigMutation = useMutation({
        mutationFn: updateSystemLogConfig,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['systemLogConfig'] });
            setEditedLogConfig({});
            setSaveMessage({ type: 'success', text: t('messages.saveSuccess') });
            setTimeout(() => setSaveMessage(null), 3000);
        },
        onError: (error: Error) => {
            setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${error.message}` });
            setTimeout(() => setSaveMessage(null), 5000);
        },
    });

    const getLogConfigValue = <K extends keyof SystemLogConfig>(key: K): SystemLogConfig[K] | undefined => {
        if (key === 'levels') {
            return undefined; // Handle levels separately
        }
        if (key in editedLogConfig) {
            return (editedLogConfig as Partial<SystemLogConfig>)[key] as SystemLogConfig[K];
        }
        return systemLogConfig?.[key];
    };

    const handleSave = () => {
        if (Object.keys(editedLogConfig).length > 0 && systemLogConfig) {
            updateLogConfigMutation.mutate({
                ...systemLogConfig,
                ...editedLogConfig,
                levels: {
                    ...systemLogConfig.levels,
                    ...(editedLogConfig.levels || {}),
                }
            });
        }
    };

    const isModified = Object.keys(editedLogConfig).length > 0;
    const inputClass = "mt-1 w-full px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors";

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-xl font-bold text-slate-800 dark:text-white">
                        {t('system.systemlogs.title')}
                    </h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                        {t('system.systemlogs.description')}
                    </p>
                </div>
                <button
                    onClick={handleSave}
                    disabled={!isModified || updateLogConfigMutation.isPending}
                    className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 dark:disabled:bg-slate-700 dark:disabled:text-slate-400 transition-colors"
                >
                    {updateLogConfigMutation.isPending ? t('system.buttons.saving') : t('system.buttons.save')}
                </button>
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

            <div className="p-4 bg-slate-50 dark:bg-slate-700/30 border border-slate-200 dark:border-slate-700 rounded-lg">
                <div className="flex gap-4">
                    <div className="text-blue-600 dark:text-blue-400">
                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="font-semibold text-slate-800 dark:text-white">
                            {t('system.systemlogs.title', 'System Log Collection')}
                        </h3>
                        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
                            {t('system.systemlogs.description', 'Configure which logs are collected from the system containers. Reducing log level can improve performance.')}
                        </p>
                    </div>
                </div>
            </div>

            {/* Enable/Disable */}
            <div className="py-3 px-4 bg-slate-50 dark:bg-slate-700/30 rounded-lg border border-slate-200 dark:border-slate-700">
                <label className="flex items-start gap-3 cursor-pointer">
                    <input
                        type="checkbox"
                        checked={getLogConfigValue('enabled') ?? true}
                        onChange={(e) => setEditedLogConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                        className="mt-0.5 w-5 h-5 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 bg-white dark:bg-slate-600"
                    />
                    <div>
                        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">
                            {t('system.systemlogs.enable.label', 'Enable System Log Collection')}
                        </span>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                            {t('system.systemlogs.enable.description', 'Collect logs from docker containers')}
                        </p>
                    </div>
                </label>
            </div>

            {/* Container Levels */}
            <div className="space-y-4">
                <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-700 pb-2">
                    <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                        {t('system.systemlogs.levels.title', 'Container Log Levels')}
                    </h3>
                    <HelpTip contentKey="system.systemlogs.help.levels" ns="settings" />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {['npg-proxy', 'npg-api', 'npg-db', 'npg-ui'].map((container) => {
                        const currentLevel = (editedLogConfig.levels?.[container]) || (systemLogConfig?.levels?.[container]) || 'info';
                        return (
                            <div key={container} className="p-3 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                                    {container}
                                </label>
                                <select
                                    value={currentLevel}
                                    onChange={(e) => {
                                        const newLevels = {
                                            ...(systemLogConfig?.levels || {}),
                                            ...(editedLogConfig.levels || {}),
                                            [container]: e.target.value
                                        };
                                        setEditedLogConfig(prev => ({ ...prev, levels: newLevels }));
                                    }}
                                    className={inputClass}
                                >
                                    <option value="debug">{t('system.systemlogs.levels.debug')}</option>
                                    <option value="info">{t('system.systemlogs.levels.info')}</option>
                                    <option value="warn">{t('system.systemlogs.levels.warn')}</option>
                                    <option value="error">{t('system.systemlogs.levels.error')}</option>
                                    <option value="fatal">{t('system.systemlogs.levels.fatal')}</option>
                                </select>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Exclude Patterns */}
            <div>
                <div className="flex justify-between items-baseline mb-2">
                    <div className="flex items-center gap-2">
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                            {t('system.systemlogs.exclude.label', 'Exclude Patterns')}
                        </label>
                        <HelpTip contentKey="system.systemlogs.help.exclude" ns="settings" />
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                        {t('system.systemlogs.exclude.count', { count: (getLogConfigValue('exclude_patterns') || []).length })}
                    </span>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                    {t('system.systemlogs.exclude.detailDescription', 'Log messages matching these patterns (regex) will be ignored. One pattern per line.')}
                </p>
                <textarea
                    value={excludePatternsText !== null
                        ? excludePatternsText
                        : (editedLogConfig.exclude_patterns !== undefined
                            ? editedLogConfig.exclude_patterns
                            : systemLogConfig?.exclude_patterns || []
                        ).join('\n')}
                    onChange={(e) => setExcludePatternsText(e.target.value)}
                    onBlur={(e) => {
                        const patterns = e.target.value.split('\n').filter(s => s.trim())
                        setEditedLogConfig(prev => ({ ...prev, exclude_patterns: patterns }))
                        setExcludePatternsText(null)
                    }}
                    className={`${inputClass} font-mono text-xs`}
                    rows={6}
                    placeholder={t('system.systemlogs.exclude.placeholder', '^/health\nHEAD /')}
                />
            </div>
        </div>
    );
}

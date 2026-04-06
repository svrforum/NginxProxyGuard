import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  getGlobalChallengeConfig,
  updateGlobalChallengeConfig,
  getChallengeStats,
  type ChallengeConfig,
  type ChallengeConfigRequest,
} from '../api/challenge';
import { HelpTip } from './common/HelpTip';

export default function ChallengeSettings() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [editedConfig, setEditedConfig] = useState<ChallengeConfigRequest>({});
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: config, isLoading } = useQuery({
    queryKey: ['challengeConfig'],
    queryFn: getGlobalChallengeConfig,
  });

  const { data: stats } = useQuery({
    queryKey: ['challengeStats'],
    queryFn: () => getChallengeStats(),
    refetchInterval: 60000, // Refresh every 30 seconds
  });

  const updateMutation = useMutation({
    mutationFn: updateGlobalChallengeConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['challengeConfig'] });
      setEditedConfig({});
      setSaveMessage({ type: 'success', text: t('captcha.messages.saveSuccess') });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (error: Error) => {
      setSaveMessage({ type: 'error', text: `${t('messages.saveFailed')}: ${error.message}` });
      setTimeout(() => setSaveMessage(null), 5000);
    },
  });

  const handleChange = <K extends keyof ChallengeConfigRequest>(key: K, value: ChallengeConfigRequest[K]) => {
    setEditedConfig((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (Object.keys(editedConfig).length > 0) {
      updateMutation.mutate(editedConfig);
    }
  };

  const getValue = <K extends keyof ChallengeConfig>(key: K): ChallengeConfig[K] | undefined => {
    if (key in editedConfig) {
      return (editedConfig as Partial<ChallengeConfig>)[key] as ChallengeConfig[K];
    }
    return config?.[key];
  };

  const isModified = Object.keys(editedConfig).length > 0;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const inputClass = "mt-1 w-full px-3 py-2.5 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold text-slate-800 dark:text-white">{t('captcha.title')}</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('captcha.description')}
          </p>
        </div>
        <button
          onClick={handleSave}
          disabled={!isModified || updateMutation.isPending}
          className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 transition-colors"
        >
          {updateMutation.isPending ? t('system.buttons.saving') : t('system.buttons.save')}
        </button>
      </div>

      {/* Save Message */}
      {saveMessage && (
        <div className={`px-4 py-3 rounded-lg text-sm font-medium ${saveMessage.type === 'success'
          ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800'
          : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800'
          }`}>
          {saveMessage.text}
        </div>
      )}

      {/* Stats Card */}
      {stats && (
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
          <h2 className="text-[13px] font-semibold text-slate-700 dark:text-slate-300 mb-4">{t('captcha.stats.title')}</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-50 dark:bg-slate-700/50 rounded-lg p-4 transition-colors">
              <p className="text-2xl font-bold text-slate-800 dark:text-white">{stats.total_challenges}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('captcha.stats.total')}</p>
            </div>
            <div className="bg-green-50 dark:bg-green-900/10 rounded-lg p-4 transition-colors">
              <p className="text-2xl font-bold text-green-700 dark:text-green-400">{stats.passed_challenges}</p>
              <p className="text-xs text-green-600 dark:text-green-500">{t('captcha.stats.passed')}</p>
            </div>
            <div className="bg-red-50 dark:bg-red-900/10 rounded-lg p-4 transition-colors">
              <p className="text-2xl font-bold text-red-700 dark:text-red-400">{stats.failed_challenges}</p>
              <p className="text-xs text-red-600 dark:text-red-500">{t('captcha.stats.failed')}</p>
            </div>
            <div className="bg-blue-50 dark:bg-blue-900/10 rounded-lg p-4 transition-colors">
              <p className="text-2xl font-bold text-blue-700 dark:text-blue-400">{stats.active_tokens}</p>
              <p className="text-xs text-blue-600 dark:text-blue-500">{t('captcha.stats.activeTokens')}</p>
            </div>
          </div>
        </div>
      )}

      {/* Configuration */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
        <h2 className="text-[13px] font-semibold text-slate-700 dark:text-slate-300 mb-4">{t('captcha.provider.title')}</h2>

        {/* Enable Toggle */}
        <div className="mb-6 py-3 px-4 rounded-lg bg-slate-50 dark:bg-slate-700/50 transition-colors">
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={getValue('enabled') ?? false}
              onChange={(e) => handleChange('enabled', e.target.checked)}
              className="mt-0.5 w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 focus:ring-offset-0 dark:bg-slate-700"
            />
            <div className="flex-1">
              <span className="text-[13px] font-semibold text-slate-700 dark:text-slate-300">{t('captcha.enable.label')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {t('captcha.enable.description')}
              </p>
            </div>
          </label>
        </div>

        {/* Provider Selection */}
        <div className="mb-6">
          <div className="flex items-center gap-1 mb-1.5">
            <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300">
              {t('captcha.provider.subTitle')}
            </label>
            <HelpTip content={
              getValue('challenge_type') === 'recaptcha_v3' ? t('captcha.provider.help.recaptcha_v3') :
                getValue('challenge_type') === 'turnstile' ? t('captcha.provider.help.turnstile') :
                  t('captcha.provider.help.recaptcha_v2')
            } />
          </div>
          <select
            value={getValue('challenge_type') ?? 'recaptcha_v2'}
            onChange={(e) => handleChange('challenge_type', e.target.value)}
            className={inputClass}
          >
            <option value="recaptcha_v2">{t('captcha.provider.recaptcha_v2')}</option>
            <option value="recaptcha_v3">{t('captcha.provider.recaptcha_v3')}</option>
            <option value="turnstile">{t('captcha.provider.turnstile')}</option>
          </select>
        </div>

        {/* API Keys */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div>
            <div className="flex items-center gap-1 mb-1.5">
              <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300">
                {t('captcha.keys.siteKey')}
              </label>
              <HelpTip content={t('captcha.keys.siteKeyDesc')} />
            </div>
            <input
              type="text"
              value={getValue('site_key') ?? ''}
              onChange={(e) => handleChange('site_key', e.target.value)}
              className={inputClass}
              placeholder="Your site key"
            />
          </div>
          <div>
            <div className="flex items-center gap-1 mb-1.5">
              <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300">
                {t('captcha.keys.secretKey')}
              </label>
              <HelpTip content={t('captcha.keys.secretKeyDesc')} />
            </div>
            <input
              type="password"
              value={(editedConfig.secret_key !== undefined) ? editedConfig.secret_key : ''}
              onChange={(e) => handleChange('secret_key', e.target.value)}
              className={inputClass}
              placeholder={config?.has_secret_key ? '••••••••••••••••' : 'Your secret key'}
            />
            <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              {config?.has_secret_key ? t('captcha.keys.secretKeySet') : t('captcha.keys.secretKeyDesc')}
            </p>
          </div>
        </div>

        {/* reCAPTCHA v3 Score */}
        {getValue('challenge_type') === 'recaptcha_v3' && (
          <div className="mb-6">
            <div className="flex items-center gap-1 mb-1.5">
              <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300">
                {t('captcha.recaptcha.score')}
              </label>
              <HelpTip content={t('captcha.recaptcha.scoreDesc')} />
            </div>
            <input
              type="number"
              step="0.1"
              min="0"
              max="1"
              value={getValue('min_score') ?? 0.5}
              onChange={(e) => handleChange('min_score', parseFloat(e.target.value))}
              className={inputClass}
            />
          </div>
        )}

        {/* Token Validity */}
        <div className="mb-6">
          <div className="flex items-center gap-1 mb-1.5">
            <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300">
              {t('captcha.tokenValidity.label')}
            </label>
            <HelpTip content={t('captcha.tokenValidity.desc')} />
          </div>
          <input
            type="number"
            value={getValue('token_validity') ?? 86400}
            onChange={(e) => handleChange('token_validity', parseInt(e.target.value))}
            className={inputClass}
          />
        </div>
      </div>

      {/* Appearance Settings */}
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
        <h2 className="text-[13px] font-semibold text-slate-700 dark:text-slate-300 mb-4">{t('captcha.appearance.title')}</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
          <div>
            <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              {t('captcha.appearance.pageTitle')}
            </label>
            <input
              type="text"
              value={getValue('page_title') ?? 'Security Check'}
              onChange={(e) => handleChange('page_title', e.target.value)}
              className={inputClass}
              placeholder="Security Check"
            />
          </div>
          <div>
            <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
              {t('captcha.appearance.theme')}
            </label>
            <select
              value={getValue('theme') ?? 'light'}
              onChange={(e) => handleChange('theme', e.target.value)}
              className={inputClass}
            >
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </div>
        </div>

        <div>
          <div className="flex items-center gap-1 mb-1.5">
            <label className="block text-[13px] font-semibold text-slate-700 dark:text-slate-300">
              {t('captcha.appearance.message')}
            </label>
            <HelpTip content={t('captcha.appearance.messageDesc')} />
          </div>
          <textarea
            value={getValue('page_message') ?? 'Please complete the security check to continue.'}
            onChange={(e) => handleChange('page_message', e.target.value)}
            rows={2}
            className={inputClass}
            placeholder="Please complete the security check to continue."
          />
        </div>
      </div>

      {/* Provider Links */}
      <div className="bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg p-4 text-sm text-blue-800 dark:text-blue-300 transition-colors">
        <strong>{t('captcha.provider.links')}</strong>
        <ul className="mt-2 space-y-1 ml-4 list-disc">
          <li>
            <a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener noreferrer" className="underline hover:text-blue-600 dark:hover:text-blue-200">
              Google reCAPTCHA Admin Console
            </a>
          </li>
          <li>
            <a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank" rel="noopener noreferrer" className="underline hover:text-blue-600 dark:hover:text-blue-200">
              Cloudflare Turnstile Dashboard
            </a>
          </li>
        </ul>
      </div>
    </div>
  );
}

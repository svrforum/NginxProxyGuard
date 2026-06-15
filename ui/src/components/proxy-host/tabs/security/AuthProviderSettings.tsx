import { useTranslation } from 'react-i18next';

interface Props {
  availableAuthProviders: Array<{ id: string; name: string; type: string }>;
  selectedProviderId: string;
  bypassPaths: string[];
  challengeActive: boolean; // geo/cloud challenge currently enabled
  onSelect: (id: string) => void;
  onBypassChange: (paths: string[]) => void;
}

export function AuthProviderSettings({ availableAuthProviders, selectedProviderId, bypassPaths, challengeActive, onSelect, onBypassChange }: Props) {
  const { t } = useTranslation('authProvider');
  return (
    <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">{t('title')}</label>
      {challengeActive && (
        <p className="mb-2 text-xs text-amber-600 dark:text-amber-400">{t('help.challengeConflict')}</p>
      )}
      <select
        value={selectedProviderId}
        disabled={challengeActive}
        onChange={(e) => onSelect(e.target.value)}
        className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:opacity-50"
      >
        <option value="">{t('list.empty')}</option>
        {availableAuthProviders.map((p) => (
          <option key={p.id} value={p.id}>{p.name} ({p.type})</option>
        ))}
      </select>
      {selectedProviderId && (
        <div className="mt-3">
          <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">{t('form.bypassPaths')}</label>
          <textarea
            value={bypassPaths.join('\n')}
            onChange={(e) => onBypassChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
            rows={3}
            placeholder="/api&#10;/healthz"
            className="w-full font-mono text-xs rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 bg-white dark:bg-slate-700 text-slate-900 dark:text-white dark:placeholder-slate-400"
          />
        </div>
      )}
    </div>
  );
}

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
        className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:opacity-50"
      >
        <option value="">{availableAuthProviders.length === 0 ? t('list.empty') : t('list.none')}</option>
        {availableAuthProviders.map((p) => (
          <option key={p.id} value={p.id}>{p.name} ({p.type})</option>
        ))}
      </select>
      {selectedProviderId && (
        <div className="mt-3">
          <label className="block text-xs text-slate-600 dark:text-slate-400 mb-1">{t('form.bypassPaths')}</label>
          {(() => {
            // Mirror the server-side rule (model.ValidateAuthBypassPath): must start with
            // "/" and contain no whitespace or nginx-breaking chars. Surface invalid lines
            // inline so the user isn't surprised by a 400 on save. (#181 follow-up)
            const invalid = bypassPaths.filter((p) => !/^\/[^\s;{}#]*$/.test(p));
            const hasInvalid = invalid.length > 0;
            return (
              <>
                <textarea
                  value={bypassPaths.join('\n')}
                  onChange={(e) => onBypassChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean))}
                  rows={3}
                  placeholder="/api&#10;/healthz"
                  className={`w-full font-mono text-xs rounded-lg border px-3 py-2 focus:outline-none focus:ring-2 transition-colors bg-white dark:bg-slate-700 text-slate-900 dark:text-white dark:placeholder-slate-400 ${hasInvalid ? 'border-red-400 dark:border-red-500 focus:border-red-500 focus:ring-red-500/30' : 'border-slate-300 dark:border-slate-600 focus:border-indigo-500 focus:ring-indigo-500/30'}`}
                />
                {hasInvalid && (
                  <p className="mt-1 text-xs text-red-600 dark:text-red-400">{t('form.bypassPathsInvalid', { paths: invalid.join(', ') })}</p>
                )}
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}

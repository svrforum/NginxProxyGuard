import { useTranslation } from 'react-i18next';
import { PRESET_LISTS, TypeBadge } from './SubscriptionTable';

interface HowItWorksProps {
  open: boolean;
  onToggle: () => void;
}

export function HowItWorks({ open, onToggle }: HowItWorksProps) {
  const { t } = useTranslation('filterSubscription');
  return (
    <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-700 p-4">
      <button onClick={onToggle}
        className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300 w-full">
        <svg className={`w-4 h-4 transition-transform ${open ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        {t('howItWorks.title')}
      </button>
      {open && (
        <div className="mt-3 pl-6 space-y-2 text-xs text-slate-600 dark:text-slate-400">
          <p>{t('howItWorks.step1')}</p>
          <p>{t('howItWorks.step2')}</p>
          <p>{t('howItWorks.step3')}</p>
          <p>{t('howItWorks.step4')}</p>
        </div>
      )}
    </div>
  );
}

interface PresetListProps {
  availablePresets: ReadonlyArray<(typeof PRESET_LISTS)[number]>;
  isPending: boolean;
  onAdd: (preset: (typeof PRESET_LISTS)[number]) => void;
}

export function PresetList({ availablePresets, isPending, onAdd }: PresetListProps) {
  const { t } = useTranslation('filterSubscription');
  if (availablePresets.length === 0) return null;
  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg shadow p-4">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">{t('presets.title')}</h3>
      <div className="space-y-2">
        {availablePresets.map(preset => (
          <div key={preset.url} className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-700/50">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-slate-900 dark:text-white">{preset.name}</span>
                  <TypeBadge type={preset.type} />
                  <a href={preset.site} target="_blank" rel="noopener noreferrer"
                    className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline"
                    onClick={e => e.stopPropagation()}>
                    {t('presets.visitSite')}
                  </a>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t(preset.description)}</p>
                <p className="text-xs text-slate-400 mt-0.5">{t(preset.detail)}</p>
              </div>
              <button onClick={() => onAdd(preset)}
                disabled={isPending}
                className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-cyan-600 hover:bg-cyan-700 text-white shrink-0 disabled:opacity-50">
                {isPending ? '...' : t('presets.add')}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

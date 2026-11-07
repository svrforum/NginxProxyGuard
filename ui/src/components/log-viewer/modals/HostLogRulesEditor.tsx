import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { HostLogRules } from '../../../types/log';

interface HostLogRulesEditorProps {
  rules: HostLogRules;
  saving: boolean;
  /** Why the last save was refused; shown above the buttons. */
  error: string | null;
  onSave: (rules: HostLogRules) => void;
  onCancel: () => void;
}

/** Entries separated by commas, spaces or lines. */
const splitWords = (value: string) => value.split(/[\s,]+/).filter(Boolean);
/** One path per line: a path may hold a comma or a space. */
const splitLines = (value: string) => value.split('\n').map((s) => s.trim()).filter(Boolean);

const inputClass =
  'w-full px-3 py-2 text-sm font-mono border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary-500';

/** The form for one host's log rules (#347). The server checks the entries. */
export function HostLogRulesEditor({ rules, saving, error, onSave, onCancel }: HostLogRulesEditorProps) {
  const { t } = useTranslation('logs');
  const [skipAll, setSkipAll] = useState(rules.skip_all);
  const [statuses, setStatuses] = useState(rules.skip_statuses.join(', '));
  const [methods, setMethods] = useState(rules.skip_methods.join(', '));
  const [paths, setPaths] = useState(rules.skip_paths.join('\n'));

  const save = () =>
    onSave({
      skip_all: skipAll,
      skip_statuses: splitWords(statuses),
      skip_methods: splitWords(methods),
      skip_paths: splitLines(paths),
    });

  return (
    <div className="mt-3 space-y-3 border-t border-slate-200 dark:border-slate-700 pt-3">
      <label className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-300 cursor-pointer">
        <input
          type="checkbox"
          checked={skipAll}
          onChange={(e) => setSkipAll(e.target.checked)}
          className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500 dark:bg-slate-700"
        />
        {t('collectionRules.skipAllLabel')}
      </label>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('collectionRules.statuses')}
          </label>
          <input
            value={statuses}
            onChange={(e) => setStatuses(e.target.value)}
            disabled={skipAll}
            placeholder="207, 3xx"
            className={inputClass}
          />
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('collectionRules.statusesHelp')}</p>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('collectionRules.methods')}
          </label>
          <input
            value={methods}
            onChange={(e) => setMethods(e.target.value)}
            disabled={skipAll}
            placeholder="PROPFIND, OPTIONS"
            className={inputClass}
          />
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('collectionRules.methodsHelp')}</p>
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
          {t('collectionRules.paths')}
        </label>
        <textarea
          value={paths}
          onChange={(e) => setPaths(e.target.value)}
          disabled={skipAll}
          rows={3}
          placeholder="/remote.php/dav/"
          className={inputClass}
        />
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('collectionRules.pathsHelp')}</p>
      </div>
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={saving}
          className="px-3 py-1.5 text-sm rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
        >
          {t('collectionRules.cancel')}
        </button>
        <button
          type="button"
          onClick={save}
          disabled={saving}
          className="px-3 py-1.5 text-sm rounded-lg bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white font-medium"
        >
          {t('collectionRules.save')}
        </button>
      </div>
    </div>
  );
}

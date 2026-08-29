import { useState } from 'react';
import { useTranslation } from 'react-i18next';

const STATUS_CLASSES = ['1xx', '2xx', '3xx', '4xx', '5xx'] as const;

interface StatusCodeFilterProps {
  /** Explicit codes the operator typed or picked. */
  codes: number[];
  /** Class tokens ('4xx'); the server expands these. */
  classes: string[];
  onChange: (codes: number[], classes: string[]) => void;
  /** Common codes offered as one-click chips. */
  quickCodes: number[];
  /** Styles the chips red for the exclusion variant. */
  variant?: 'include' | 'exclude';
}

/**
 * Status-code filter that accepts a whole class ("4xx"), a one-click common
 * code, or any code typed by hand — 499, 444 and 52x are real and were not
 * reachable from the old fixed chip list.
 *
 * Classes travel as tokens and are expanded on the server: expanding "4xx"
 * in the browser would put 100 repeated query parameters on the URL for one
 * chip, and all four classes would run past nginx's default header buffer.
 */
export function StatusCodeFilter({ codes, classes, onChange, quickCodes, variant = 'include' }: StatusCodeFilterProps) {
  const { t } = useTranslation('logs');
  const [draft, setDraft] = useState('');
  const [error, setError] = useState<string | null>(null);

  const activeChip = variant === 'exclude'
    ? 'bg-red-500 text-white'
    : 'bg-primary-500 text-white';
  const idleChip = 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-600';

  const toggleClass = (cls: string) => {
    onChange(codes, classes.includes(cls) ? classes.filter(c => c !== cls) : [...classes, cls]);
  };

  const toggleCode = (code: number) => {
    onChange(codes.includes(code) ? codes.filter(c => c !== code) : [...codes, code], classes);
  };

  // Accepts "404", "404,499", "4xx" and any mix, so a pasted list works.
  const commitDraft = () => {
    const tokens = draft.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (tokens.length === 0) {
      setDraft('');
      setError(null);
      return;
    }
    const nextCodes = [...codes];
    const nextClasses = [...classes];
    for (const token of tokens) {
      if (/^[1-5]xx$/i.test(token)) {
        const cls = token.toLowerCase();
        if (!nextClasses.includes(cls)) nextClasses.push(cls);
        continue;
      }
      const code = Number(token);
      if (!Number.isInteger(code) || code < 100 || code > 599) {
        setError(t('filters.statusCodeInvalid', { value: token }));
        return;
      }
      if (!nextCodes.includes(code)) nextCodes.push(code);
    }
    onChange(nextCodes, nextClasses);
    setDraft('');
    setError(null);
  };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1">
        <span className="text-xs text-slate-500 dark:text-slate-400 mr-1">{t('filters.statusClass')}:</span>
        {STATUS_CLASSES.map(cls => (
          <button
            key={cls}
            type="button"
            onClick={() => toggleClass(cls)}
            className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${classes.includes(cls) ? activeChip : idleChip}`}
          >
            {cls}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1">
        <span className="text-xs text-slate-500 dark:text-slate-400 mr-1">{t('filters.statusCommon')}:</span>
        {quickCodes.map(code => (
          <button
            key={code}
            type="button"
            onClick={() => toggleCode(code)}
            className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${codes.includes(code) ? activeChip : idleChip}`}
          >
            {code}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <input
          type="text"
          value={draft}
          onChange={(e) => { setDraft(e.target.value); setError(null); }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              commitDraft();
            }
          }}
          onBlur={commitDraft}
          placeholder={t('filters.statusCodePlaceholder')}
          className="flex-1 px-2 py-1 text-xs rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200"
        />
      </div>

      {error && (
        <p className="text-xs text-red-600 dark:text-red-400">{error}</p>
      )}

      {(codes.length > 0 || classes.length > 0) && (
        <div className="flex flex-wrap gap-1">
          {classes.map(cls => (
            <span key={`c-${cls}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
              {cls}
              <button type="button" onClick={() => toggleClass(cls)} className="hover:text-red-500" aria-label={t('filters.remove')}>×</button>
            </span>
          ))}
          {codes.map(code => (
            <span key={`n-${code}`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200">
              {code}
              <button type="button" onClick={() => toggleCode(code)} className="hover:text-red-500" aria-label={t('filters.remove')}>×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

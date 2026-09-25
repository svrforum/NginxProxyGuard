import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchWAFEventRules, type WAFEventRule } from '../../../api/waf';
import type { Log } from '../../../types/log';

/**
 * Every rule behind one WAF event, as a checklist.
 *
 * CRS blocks on the SUM of the rules a request matched, and a single probe
 * usually matches several. The event row names only the first, so disabling
 * "the" rule left the request blocked under the next number — 942190, then
 * 942270, then 942360 before it got through — which looks exactly like an
 * exclusion that did not work (#306). Listing them all lets the operator
 * switch off what was actually responsible in one go, and shows which ones
 * are already switched off for the chosen scope instead of answering with a
 * 409.
 */

const normPath = (v?: string) => (v ?? '').replace(/\/+$/, '') || '/';

/** Whether an existing exclusion already covers this rule for the chosen scope. */
function isCovered(rule: WAFEventRule, scopeType: string, scopeValue: string): boolean {
  return rule.excluded.some((e) =>
    e.scope_type === 'host' ||
    (e.scope_type === scopeType &&
      (scopeType === 'uri' ? normPath(e.scope_value) === normPath(scopeValue) : (e.scope_value ?? '') === scopeValue.trim())),
  );
}

interface Props {
  log: Log;
  scopeType: 'host' | 'uri' | 'param';
  scopeValue: string;
  selected: number[];
  setSelected: (ids: number[]) => void;
}

export function ContributingRules({ log, scopeType, scopeValue, selected, setSelected }: Props) {
  const { t } = useTranslation('logs');
  const { data, isLoading, isError } = useQuery({
    queryKey: ['waf-event-rules', log.id],
    queryFn: () => fetchWAFEventRules(log.id, log.created_at),
    enabled: !!log.id && !!log.created_at,
    staleTime: 10_000,
  });

  const rules = data?.rules ?? [];
  const open = rules.filter((r) => !isCovered(r, scopeType, scopeValue));

  // Default to every rule not already covered — that is the set that blocked
  // the request. Re-run when the scope changes, because coverage does.
  useEffect(() => {
    if (!data) return;
    setSelected(open.map((r) => r.rule_id));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, scopeType, scopeValue]);

  if (isLoading) {
    return <p className="text-xs text-slate-500 dark:text-slate-400">{t('disableRule.contributing.loading')}</p>;
  }
  // No audit record to read (old row, or not a modsec event): the form falls
  // back to the single rule on the row, as before.
  if (isError || rules.length === 0) return null;

  const toggle = (id: number) =>
    setSelected(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);

  return (
    <div data-testid="contributing-rules">
      <label className="mb-1 block text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
        {t('disableRule.contributing.title', { count: rules.length })}
      </label>
      {rules.length > 1 && (
        <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">{t('disableRule.contributing.hint')}</p>
      )}
      <ul className="max-h-48 space-y-1 overflow-y-auto">
        {rules.map((r) => {
          const covered = isCovered(r, scopeType, scopeValue);
          return (
            <li key={r.rule_id}>
              <label className={`flex items-start gap-2 rounded px-2 py-1 text-sm ${covered ? 'opacity-60' : 'hover:bg-slate-50 dark:hover:bg-slate-700/40'}`}>
                <input
                  type="checkbox"
                  className="mt-0.5"
                  data-testid={`contributing-rule-${r.rule_id}`}
                  disabled={covered}
                  checked={covered || selected.includes(r.rule_id)}
                  onChange={() => toggle(r.rule_id)}
                />
                <span className="min-w-0">
                  <span className="font-mono text-slate-900 dark:text-white">{r.rule_id}</span>{' '}
                  <span className="text-slate-600 dark:text-slate-300">{r.message}</span>
                  {covered && (
                    <span className="ml-1 rounded bg-slate-200 px-1 text-[10px] text-slate-600 dark:bg-slate-600 dark:text-slate-300">
                      {t('disableRule.contributing.alreadyExcluded')}
                    </span>
                  )}
                </span>
              </label>
            </li>
          );
        })}
      </ul>
      {open.length === 0 && (
        <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">{t('disableRule.contributing.allCovered')}</p>
      )}
    </div>
  );
}

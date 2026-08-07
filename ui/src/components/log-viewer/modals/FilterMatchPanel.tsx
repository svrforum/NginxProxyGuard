import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { matchFilterSubscriptions } from '../../../api/filter-subscriptions'
import type { Log } from '../../../types/log'

/**
 * Which subscription blocked this request (#230).
 *
 * A filter_subscription block in the access log says only THAT a list matched.
 * nginx resolves every subscribed range through one shared radix tree, so it
 * cannot say which list a hit came from — and the operator was left disabling
 * subscriptions one at a time until the block stopped.
 *
 * The answer is looked up here rather than tagged onto the request: it costs
 * nothing per request, and it works on log rows that were written before this
 * existed.
 */
export function FilterMatchPanel({ log }: { log: Log }) {
  const { t } = useTranslation('logs')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['filter-match', log.client_ip, log.http_user_agent],
    queryFn: () => matchFilterSubscriptions(log.client_ip ?? '', log.http_user_agent ?? ''),
    enabled: !!(log.client_ip || log.http_user_agent),
    staleTime: 60_000,
  })

  const matches = [...(data?.ip_matches ?? []), ...(data?.user_agent_matches ?? [])]
  const active = matches.filter((m) => m.enabled)
  const inactive = matches.filter((m) => !m.enabled)

  return (
    <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-900/40 dark:bg-amber-900/10">
      <div className="text-xs font-semibold uppercase tracking-wide text-amber-800 dark:text-amber-300">
        {t('filterMatch.title')}
      </div>

      {isLoading && <p className="mt-1 text-sm text-slate-500">{t('filterMatch.loading')}</p>}
      {isError && <p className="mt-1 text-sm text-red-600 dark:text-red-400">{t('filterMatch.failed')}</p>}

      {!isLoading && !isError && active.length === 0 && (
        // A block with no live match is worth saying out loud: the list was
        // probably edited or the entry excluded after the request was refused.
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{t('filterMatch.none')}</p>
      )}

      {active.map((m) => (
        <div key={`${m.subscription_id}-${m.matched_value}`} className="mt-1.5 text-sm">
          <span className="font-medium text-slate-900 dark:text-white">{m.subscription_name}</span>
          <span className="ml-2 rounded bg-white px-1.5 py-0.5 font-mono text-xs text-slate-600 dark:bg-slate-700 dark:text-slate-300">
            {m.matched_value}
          </span>
          {m.reason && <span className="ml-2 text-xs text-slate-500 dark:text-slate-400">{m.reason}</span>}
        </div>
      ))}

      {inactive.length > 0 && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          {t('filterMatch.alsoDisabled', { names: inactive.map((m) => m.subscription_name).join(', ') })}
        </p>
      )}
    </div>
  )
}

export default FilterMatchPanel

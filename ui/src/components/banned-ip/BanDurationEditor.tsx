import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { updateBanDuration } from '../../api/banned-ips'
import { BAN_DURATIONS } from './banDurations'

/**
 * Changes how long a ban still has to run, from the ban's own detail view.
 *
 * Before this, changing a duration meant unbanning and banning again, which
 * loses the ban's history. The new duration counts from NOW rather than from
 * when the ban started: "give this one another day" is what operators actually
 * do, and re-dating from the original start would silently expire a ban whose
 * window has already passed. (#252)
 */
export function BanDurationEditor({ banId, isPermanent }: { banId: string; isPermanent: boolean }) {
  const { t } = useTranslation(['waf', 'common'])
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [seconds, setSeconds] = useState<number>(86400)
  const [error, setError] = useState('')

  const save = useMutation({
    mutationFn: () => updateBanDuration(banId, seconds),
    onSuccess: () => {
      setOpen(false)
      setError('')
      // Both the list and this IP's own panels read the expiry.
      queryClient.invalidateQueries({ queryKey: ['bannedIPs'] })
      queryClient.invalidateQueries({ queryKey: ['ip-ban-history'] })
      queryClient.invalidateQueries({ queryKey: ['banned-ip-stats'] })
    },
    onError: (e: unknown) => setError(e instanceof Error ? e.message : t('bannedIp.duration.saveFailed')),
  })

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-xs text-red-700 underline hover:no-underline dark:text-red-300"
      >
        {isPermanent ? t('bannedIp.duration.editPermanent') : t('bannedIp.duration.edit')}
      </button>
    )
  }

  return (
    <span className="flex flex-wrap items-center gap-2">
      <select
        aria-label="ban-duration"
        value={seconds}
        onChange={(e) => setSeconds(parseInt(e.target.value))}
        className="rounded border border-red-200 bg-white px-2 py-1 text-xs text-slate-800 dark:border-red-900/40 dark:bg-slate-700 dark:text-slate-100"
      >
        {BAN_DURATIONS.map((d) => (
          <option key={d.key} value={d.seconds}>
            {t(`bannedIp.durations.${d.key}`)}
          </option>
        ))}
      </select>
      <button
        onClick={() => save.mutate()}
        disabled={save.isPending}
        className="rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
      >
        {t('common:buttons.save')}
      </button>
      <button
        onClick={() => {
          setOpen(false)
          setError('')
        }}
        className="px-2 py-1 text-xs text-slate-600 hover:underline dark:text-slate-300"
      >
        {t('common:buttons.cancel')}
      </button>
      <span className="w-full text-xs text-slate-500 dark:text-slate-400">
        {t('bannedIp.duration.fromNowHint')}
      </span>
      {error && <span className="w-full text-xs text-red-600 dark:text-red-400">{error}</span>}
    </span>
  )
}

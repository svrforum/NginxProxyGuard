import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  deleteNotificationChannel,
  listNotificationChannels,
  listNotificationDeliveries,
  testNotificationChannel,
} from '../../api/notification'
import { type NotificationChannel, type NotificationChannelType } from '../../types/notification'
import { usePermissions } from '../../hooks/usePermissions'
import { ModalShell } from '../common/ModalShell'
import { NotificationChannelForm } from './notification/NotificationChannelForm'
import { browserOffsetMinutes, browserZone, fmt, humanError } from './notification/shared'

/**
 * Notification channels (#221).
 *
 * Two things here are load-bearing rather than decoration. A channel that has
 * been failing shows why on its own card, because the failure mode of a
 * notification system is silence and an operator cannot debug silence. And the
 * template help lists what is available *and* states what is deliberately not,
 * so nobody goes looking for a way to put request headers in a Discord message.
 */
export function NotificationChannelManager() {
  const { t } = useTranslation(['settings', 'common'])
  const tr = (k: string, o?: Record<string, unknown>) => String(t(k, o ?? {}))
  const qc = useQueryClient()
  const { can } = usePermissions()
  const canWrite = can('settings:write')

  const [editing, setEditing] = useState<NotificationChannel | null>(null)
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState<NotificationChannel | null>(null)
  const [logFor, setLogFor] = useState<NotificationChannel | null>(null)
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null)

  const { data, isLoading } = useQuery({ queryKey: ['notification-channels'], queryFn: listNotificationChannels })
  const channels = data?.data ?? []
  const events = data?.events ?? []
  // The hour is compared against the API container's clock, so the label must
  // name the server's zone. When it differs from the browser's, say so — this
  // silently sent a Seoul operator's 9am summary at 18:00 local.
  const serverZone = data?.timezone?.name ?? browserZone
  const zoneMismatch =
    data?.timezone !== undefined && data.timezone.offset_minutes !== browserOffsetMinutes

  const { data: deliveries } = useQuery({
    queryKey: ['notification-deliveries', logFor?.id],
    queryFn: () => listNotificationDeliveries(logFor!.id),
    enabled: !!logFor,
  })

  const close = () => { setEditing(null); setCreating(false) }

  const remove = useMutation({
    mutationFn: (id: string) => deleteNotificationChannel(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['notification-channels'] }); setDeleting(null) },
  })

  const test = useMutation({
    mutationFn: (v: { id: string; event?: string }) => testNotificationChannel(v.id, v.event),
    onSuccess: (_r, v) => {
      setTestResult({ id: v.id, ok: true, message: tr('notifications.testSent') })
      qc.invalidateQueries({ queryKey: ['notification-channels'] })
      qc.invalidateQueries({ queryKey: ['notification-deliveries'] })
    },
    onError: (e: Error, v) => {
      setTestResult({ id: v.id, ok: false, message: humanError(e, tr) })
      qc.invalidateQueries({ queryKey: ['notification-channels'] })
      qc.invalidateQueries({ queryKey: ['notification-deliveries'] })
    },
  })

  const openCreate = () => { setCreating(true); setEditing(null) }
  const openEdit = (c: NotificationChannel) => { setEditing(c); setCreating(false) }

  const typeLabel = (ty: NotificationChannelType) =>
    ty === 'discord' ? 'Discord' : ty === 'telegram' ? 'Telegram' : tr('notifications.types.webhook')

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{tr('notifications.title')}</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{tr('notifications.subtitle')}</p>
        </div>
        <button
          type="button"
          onClick={openCreate}
          disabled={!canWrite}
          title={canWrite ? undefined : tr('notifications.noPermission')}
          className="shrink-0 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
        >
          + {tr('notifications.add')}
        </button>
      </div>

      <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-900/40 dark:text-slate-300">
        {tr('notifications.quietByDesign')}
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">{tr('common:loading', { defaultValue: 'Loading…' })}</p>
      ) : channels.length === 0 ? (
        <p className="rounded-lg border border-dashed border-slate-300 px-4 py-8 text-center text-sm text-slate-500 dark:border-slate-700">
          {tr('notifications.empty')}
        </p>
      ) : (
        <div data-testid="notification-channel-list" className="space-y-3">
          {channels.map((c) => (
            <div key={c.id} className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-900 dark:text-white">{c.name}</span>
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-500 dark:bg-slate-700 dark:text-slate-300">
                      {typeLabel(c.type)}
                    </span>
                    {!c.enabled && (
                      <span className="rounded bg-slate-200 px-2 py-0.5 text-[11px] font-semibold uppercase text-slate-600 dark:bg-slate-600 dark:text-slate-200">
                        {tr('notifications.disabled')}
                      </span>
                    )}
                    {c.digest_enabled && (
                      <span className="rounded bg-indigo-50 px-2 py-0.5 text-[11px] font-semibold text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300">
                        {tr('notifications.digestBadge', { hour: String(c.digest_hour).padStart(2, '0') })}
                      </span>
                    )}
                  </div>
                  {/* Both counts, because "이벤트 3개" hid the summary-only
                      subscriptions entirely — a channel with 2 immediate and 4
                      summary-only events read as if it had 2. And the last
                      delivery, so a working channel and a silent one do not
                      look identical without opening the history. */}
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {(c.events ?? []).length === 0 && (c.digest_events ?? []).length === 0
                      ? tr('notifications.noEvents')
                      : [
                          (c.events ?? []).length > 0
                            ? tr('notifications.eventCount', { count: (c.events ?? []).length })
                            : null,
                          (c.digest_events ?? []).length > 0
                            ? tr('notifications.digestEventCount', { count: (c.digest_events ?? []).length })
                            : null,
                        ]
                          .filter(Boolean)
                          .join(' · ')}
                    <span className="ml-2 text-slate-400 dark:text-slate-500">
                      {tr('notifications.lastDelivery', { when: fmt(c.last_success_at) })}
                    </span>
                  </p>

                  {/* The failure mode of a notification system is silence, so a
                      failing channel explains itself here rather than in a log. */}
                  {c.consecutive_failures > 0 && (
                    <p data-testid="notification-channel-error" className="mt-2 rounded-md bg-red-50 px-2 py-1.5 text-xs text-red-700 dark:bg-red-900/20 dark:text-red-300">
                      {tr('notifications.failing', { count: c.consecutive_failures })}
                      {c.last_error && <span className="mt-0.5 block font-mono text-[11px] opacity-80">{c.last_error}</span>}
                    </p>
                  )}
                  {testResult?.id === c.id && (
                    <p
                      data-testid="notification-test-result"
                      className={`mt-2 rounded-md px-2 py-1.5 text-xs ${
                        testResult.ok
                          ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300'
                          : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300'
                      }`}
                    >
                      {testResult.message}
                    </p>
                  )}
                </div>

                <div className="flex shrink-0 flex-wrap gap-2">
                  <button
                    type="button"
                    data-testid={`test-${c.name}`}
                    onClick={() => { setTestResult(null); test.mutate({ id: c.id }) }}
                    disabled={!canWrite || test.isPending}
                    title={canWrite ? undefined : tr('notifications.noPermission')}
                    className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    {tr('notifications.test')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setLogFor(c)}
                    className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    {tr('notifications.history')}
                  </button>
                  <button
                    type="button"
                    onClick={() => openEdit(c)}
                    className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    {canWrite ? tr('common:buttons.edit') : tr('common:buttons.view', { defaultValue: 'View' })}
                  </button>
                  <button
                    type="button"
                    onClick={() => setDeleting(c)}
                    disabled={!canWrite}
                    title={canWrite ? undefined : tr('notifications.noPermission')}
                    className="rounded-lg border border-red-200 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 disabled:opacity-50 dark:border-red-900 dark:text-red-300 dark:hover:bg-red-900/20"
                  >
                    {tr('common:buttons.delete')}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* The form lives in its own file: it owns a draft of one channel,
          while this component owns the list of them. */}
      {(creating || editing !== null) && (
        <NotificationChannelForm
          channel={editing}
          creating={creating}
          events={events}
          serverZone={serverZone}
          zoneMismatch={zoneMismatch}
          canWrite={canWrite}
          onClose={close}
        />
      )}
      {/* ── delivery history ─────────────────────────────────────── */}
      <ModalShell isOpen={logFor !== null} onClose={() => setLogFor(null)} panelClassName="max-w-2xl" labelledById="notification-log-title" bodyScroll>
        {/* The history is as long as the channel is old, so the same pinned
            frame applies: which channel this is stays on screen while reading. */}
        <div className="shrink-0 border-b border-slate-200 px-6 py-4 dark:border-slate-700">
          <h3 id="notification-log-title" className="text-lg font-semibold text-slate-900 dark:text-white">
            {tr('notifications.historyTitle', { name: logFor?.name ?? '' })}
          </h3>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
          <div className="space-y-2">
            {(deliveries?.data ?? []).length === 0 ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">{tr('notifications.noHistory')}</p>
            ) : (
              (deliveries?.data ?? []).map((d) => (
                <div key={d.id} className="rounded-lg border border-slate-200 px-3 py-2 text-xs dark:border-slate-700">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                        d.status === 'sent'
                          ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                          : d.status === 'queued'
                            ? 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'
                            : 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                      }`}
                    >
                      {d.status}
                    </span>
                    <span className="font-mono text-slate-600 dark:text-slate-300">{d.event_key}</span>
                    <span className="text-slate-400">{fmt(d.created_at)}</span>
                    {d.attempts > 1 && <span className="text-slate-400">{tr('notifications.attempts', { count: d.attempts })}</span>}
                  </div>
                  {d.last_error && <p className="mt-1 font-mono text-[11px] text-red-600 dark:text-red-400">{d.last_error}</p>}
                </div>
              ))
            )}
          </div>
        </div>
        <div className="flex shrink-0 justify-end border-t border-slate-200 px-6 py-4 dark:border-slate-700">
          <button type="button" onClick={() => setLogFor(null)} className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
            {tr('common:buttons.close')}
          </button>
        </div>
      </ModalShell>

      {/* ── delete ───────────────────────────────────────────────── */}
      <ModalShell isOpen={deleting !== null} onClose={() => setDeleting(null)} panelClassName="max-w-md" labelledById="notification-delete-title">
        <div className="p-6">
          <h3 id="notification-delete-title" className="text-lg font-semibold text-slate-900 dark:text-white">{tr('notifications.deleteTitle')}</h3>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{tr('notifications.deleteBody', { name: deleting?.name ?? '' })}</p>
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" onClick={() => setDeleting(null)} className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {tr('common:buttons.cancel')}
            </button>
            <button
              type="button"
              onClick={() => deleting && remove.mutate(deleting.id)}
              disabled={remove.isPending}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              {tr('common:buttons.delete')}
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  )
}

export default NotificationChannelManager

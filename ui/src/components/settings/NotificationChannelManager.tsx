import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  createNotificationChannel,
  deleteNotificationChannel,
  listNotificationChannels,
  listNotificationDeliveries,
  detectTelegramChats,
  testNotificationChannel,
  updateNotificationChannel,
} from '../../api/notification'
import {
  TEMPLATE_PLACEHOLDERS,
  type NotificationChannel,
  type NotificationChannelRequest,
  type NotificationChannelType,
  type TelegramChat,
} from '../../types/notification'
import { usePermissions } from '../../hooks/usePermissions'
import { ModalShell } from '../common/ModalShell'

const emptyForm = (): NotificationChannelRequest => ({
  name: '',
  type: 'webhook',
  enabled: true,
  config: {},
  events: [],
  digest_events: [],
  rich_format: true,
  // Defaults to the language the operator is configuring in: somebody
  // working in Korean does not expect English alerts.
  language: (localStorage.getItem('npg_language') === 'ko' ? 'ko' : 'en'),
  // Prefilled with the address the operator is looking at, which is almost
  // always the one they want in the message.
  dashboard_url: window.location.origin,
  digest_enabled: false,
  digest_hour: 9,
  allow_private_target: false,
  template: '',
})

const toForm = (c: NotificationChannel): NotificationChannelRequest => ({
  name: c.name,
  type: c.type,
  enabled: c.enabled,
  config: { ...c.config },
  events: [...(c.events ?? [])],
  digest_events: [...(c.digest_events ?? [])],
  rich_format: c.rich_format,
  language: c.language || 'en',
  dashboard_url: c.dashboard_url ?? '',
  digest_enabled: c.digest_enabled,
  digest_hour: c.digest_hour,
  allow_private_target: c.allow_private_target,
  template: c.template ?? '',
})

/** The timezone digest_hour is actually interpreted in. There is no timezone
 *  setting in NPG; the API container follows TZ and defaults to UTC, so the
 *  label states what the browser resolves rather than letting the operator
 *  guess. */
const localZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'

const fmt = (iso?: string) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

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
  const [form, setForm] = useState<NotificationChannelRequest>(emptyForm())
  const [formError, setFormError] = useState('')
  const [deleting, setDeleting] = useState<NotificationChannel | null>(null)
  const [logFor, setLogFor] = useState<NotificationChannel | null>(null)
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; message: string } | null>(null)
  const [chats, setChats] = useState<{ list: TelegramChat[]; error: string } | null>(null)
  const [detecting, setDetecting] = useState(false)

  const { data, isLoading } = useQuery({ queryKey: ['notification-channels'], queryFn: listNotificationChannels })
  const channels = data?.data ?? []
  const events = data?.events ?? []

  const { data: deliveries } = useQuery({
    queryKey: ['notification-deliveries', logFor?.id],
    queryFn: () => listNotificationDeliveries(logFor!.id),
    enabled: !!logFor,
  })

  const close = () => { setEditing(null); setCreating(false); setFormError('') }

  const save = useMutation({
    mutationFn: (payload: NotificationChannelRequest) =>
      editing ? updateNotificationChannel(editing.id, payload) : createNotificationChannel(payload),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['notification-channels'] }); close() },
    onError: (e: Error) => setFormError(e.message),
  })

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
      setTestResult({ id: v.id, ok: false, message: e.message })
      qc.invalidateQueries({ queryKey: ['notification-channels'] })
      qc.invalidateQueries({ queryKey: ['notification-deliveries'] })
    },
  })

  const detect = async () => {
    setDetecting(true)
    setChats(null)
    try {
      const r = await detectTelegramChats(form.config.bot_token ?? '', editing?.id)
      setChats({ list: r.data ?? [], error: '' })
    } catch (e) {
      setChats({ list: [], error: e instanceof Error ? e.message : String(e) })
    } finally {
      setDetecting(false)
    }
  }

  const openCreate = () => { setForm(emptyForm()); setCreating(true); setEditing(null); setFormError(''); setChats(null) }
  const openEdit = (c: NotificationChannel) => { setForm(toForm(c)); setEditing(c); setCreating(false); setFormError(''); setChats(null) }

  const setConfig = (key: string, value: string) =>
    setForm((f) => ({ ...f, config: { ...f.config, [key]: value } }))

  type EventMode = 'off' | 'immediate' | 'digest'
  const modeOf = (key: string): EventMode =>
    form.events.includes(key) ? 'immediate' : form.digest_events.includes(key) ? 'digest' : 'off'

  // Three states rather than a checkbox: "send me this the moment it happens"
  // and "just mention it in the daily summary" are genuinely different answers,
  // and forcing both into one tick makes a busy channel the only option.
  const setEventMode = (key: string, mode: EventMode) =>
    setForm((f) => ({
      ...f,
      events: mode === 'immediate' ? [...new Set([...f.events, key])] : f.events.filter((e) => e !== key),
      digest_events: mode === 'digest' ? [...new Set([...f.digest_events, key])] : f.digest_events.filter((e) => e !== key),
      digest_enabled: mode === 'digest' ? true : f.digest_enabled,
    }))

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
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {(c.events ?? []).length === 0
                      ? tr('notifications.noEvents')
                      : tr('notifications.eventCount', { count: (c.events ?? []).length })}
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
                    aria-label={`test-${c.name}`}
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

      {/* ── form ─────────────────────────────────────────────────── */}
      <ModalShell
        isOpen={creating || editing !== null}
        onClose={close}
        closeOnBackdrop={false}
        panelClassName="max-w-2xl"
        labelledById="notification-form-title"
        bodyScroll
      >
        {/* The form runs two to three screens tall, so its title and its Save
            button stay pinned and only the middle scrolls. */}
        <div className="shrink-0 border-b border-slate-200 px-6 py-4 dark:border-slate-700">
          <h3 id="notification-form-title" className="text-lg font-semibold text-slate-900 dark:text-white">
            {editing ? tr('notifications.editTitle') : tr('notifications.addTitle')}
          </h3>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={tr('notifications.fields.name')}>
                <input aria-label="notify-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputCls} />
              </Field>
              <Field label={tr('notifications.fields.type')}>
                <select
                  aria-label="notify-type"
                  value={form.type}
                  onChange={(e) => setForm({ ...form, type: e.target.value as NotificationChannelType, config: {} })}
                  className={inputCls}
                >
                  <option value="webhook">{tr('notifications.types.webhook')}</option>
                  <option value="discord">Discord</option>
                  <option value="telegram">Telegram</option>
                </select>
              </Field>
            </div>

            {/* What to do at the provider, before any field is filled in. The
                bot token and chat id are not discoverable without this, and the
                chat id is shown nowhere in Telegram's own interface. */}
            <div data-testid="notify-guide" className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 dark:border-slate-700 dark:bg-slate-900/40">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                {tr(`notifications.guides.${form.type}.title`)}
              </p>
              <ol className="mt-1.5 list-decimal space-y-1 pl-4 text-xs text-slate-600 dark:text-slate-300">
                {(t(`notifications.guides.${form.type}.steps`, { returnObjects: true, defaultValue: [] }) as unknown as string[]).map(
                  (line, i) => <li key={i}>{line}</li>,
                )}
              </ol>
            </div>

            {form.type === 'telegram' ? (
              <>
                <Field label={tr('notifications.fields.botToken')} hint={editing ? tr('notifications.fields.secretKeepHint') : tr('notifications.fields.botTokenHint')}>
                  <input aria-label="notify-bot-token" type="password" value={form.config.bot_token ?? ''} onChange={(e) => setConfig('bot_token', e.target.value)} className={inputCls} />
                </Field>
                <Field label={tr('notifications.fields.chatId')} hint={tr('notifications.fields.chatIdHint')}>
                  <div className="flex gap-2">
                    <input aria-label="notify-chat-id" value={form.config.chat_id ?? ''} onChange={(e) => setConfig('chat_id', e.target.value)} className={inputCls} />
                    <button
                      type="button"
                      aria-label="notify-detect-chat"
                      onClick={detect}
                      disabled={detecting || !(form.config.bot_token || editing)}
                      className="shrink-0 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
                    >
                      {detecting ? tr('notifications.detecting') : tr('notifications.detect')}
                    </button>
                  </div>
                </Field>
                {chats && (
                  <div data-testid="notify-chat-results" className="rounded-lg border border-slate-200 px-3 py-2 text-xs dark:border-slate-700">
                    {chats.error ? (
                      <p className="text-red-600 dark:text-red-400">{chats.error}</p>
                    ) : chats.list.length === 0 ? (
                      <p className="text-amber-700 dark:text-amber-400">{tr('notifications.detectEmpty')}</p>
                    ) : (
                      <>
                        <p className="mb-1.5 text-slate-500 dark:text-slate-400">{tr('notifications.detectPick')}</p>
                        <div className="flex flex-wrap gap-1.5">
                          {chats.list.map((c) => (
                            <button
                              key={c.id}
                              type="button"
                              onClick={() => setConfig('chat_id', c.id)}
                              className="rounded border border-slate-300 px-2 py-1 text-left hover:bg-slate-50 dark:border-slate-600 dark:hover:bg-slate-700"
                            >
                              <span className="font-medium text-slate-700 dark:text-slate-200">{c.title || c.type}</span>
                              <span className="ml-1.5 font-mono text-[11px] text-slate-500">{c.id}</span>
                            </button>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </>
            ) : (
              <>
                <Field
                  label={form.type === 'discord' ? tr('notifications.fields.discordUrl') : tr('notifications.fields.webhookUrl')}
                  hint={form.type === 'discord' ? tr('notifications.fields.discordUrlHint') : tr('notifications.fields.webhookUrlHint')}
                >
                  <input aria-label="notify-url" value={form.config.url ?? ''} onChange={(e) => setConfig('url', e.target.value)} className={inputCls} />
                </Field>
                {form.type === 'webhook' && (
                  <>
                    <Field label={tr('notifications.fields.payloadFormat')} hint={tr('notifications.fields.payloadFormatHint')}>
                      <select
                        data-testid="notify-payload-format"
                        value={form.config['payload_format'] ?? 'json'}
                        onChange={(e) => setConfig('payload_format', e.target.value)}
                        className={inputCls}
                      >
                        <option value="json">{tr('notifications.payloadFormats.json')}</option>
                        <option value="text">{tr('notifications.payloadFormats.text')}</option>
                      </select>
                    </Field>
                    <Field label={tr('notifications.fields.authHeader')} hint={tr('notifications.fields.authHeaderHint')}>
                      <input
                        aria-label="notify-auth-header"
                        type="password"
                        value={form.config['header_Authorization'] ?? ''}
                        onChange={(e) => setConfig('header_Authorization', e.target.value)}
                        className={inputCls}
                      />
                    </Field>
                  </>
                )}
                <label className="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200">
                  <input
                    type="checkbox"
                    aria-label="notify-allow-private"
                    checked={form.allow_private_target}
                    onChange={(e) => setForm({ ...form, allow_private_target: e.target.checked })}
                    className="mt-0.5 rounded"
                  />
                  <span>
                    {tr('notifications.fields.allowPrivate')}
                    <span className="mt-0.5 block text-xs text-slate-500 dark:text-slate-400">{tr('notifications.fields.allowPrivateHint')}</span>
                  </span>
                </label>
              </>
            )}

            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
              <input type="checkbox" aria-label="notify-enabled" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} className="rounded" />
              {tr('notifications.fields.enabled')}
            </label>

            <hr className="border-slate-200 dark:border-slate-700" />

            <div>
              <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{tr('notifications.whatToSend')}</h4>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{tr('notifications.whatToSendHint')}</p>
              <div data-testid="notify-event-list" className="mt-2 space-y-1.5">
                {events.map((ev) => {
                  const mode = modeOf(ev.key)
                  return (
                    <div
                      key={ev.key}
                      className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-200 px-2.5 py-2 dark:border-slate-700"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className={`h-2 w-2 shrink-0 rounded-full ${
                              ev.severity === 'error'
                                ? 'bg-red-500'
                                : ev.severity === 'warning'
                                  ? 'bg-amber-500'
                                  : 'bg-emerald-500'
                            }`}
                            title={tr(`notifications.severity.${ev.severity}`)}
                          />
                          <span className="text-sm font-medium text-slate-800 dark:text-slate-100">
                            {tr(`notifications.events.${ev.key}.label`, { defaultValue: ev.key })}
                          </span>
                          {ev.batched && (
                            <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] text-slate-500 dark:bg-slate-700 dark:text-slate-300">
                              {tr('notifications.batched')}
                            </span>
                          )}
                        </div>
                        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                          {tr(`notifications.events.${ev.key}.desc`, { defaultValue: '' })}
                        </p>
                      </div>

                      <div className="flex shrink-0 items-center gap-1">
                        {(['off', 'immediate', 'digest'] as const).map((m) => (
                          <button
                            key={m}
                            type="button"
                            aria-label={`notify-event-${ev.key}-${m}`}
                            aria-pressed={mode === m}
                            onClick={() => setEventMode(ev.key, m)}
                            className={`rounded px-2 py-1 text-[11px] transition-colors ${
                              mode === m
                                ? 'bg-primary-600 text-white'
                                : 'border border-slate-300 text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700'
                            }`}
                          >
                            {tr(`notifications.modes.${m}`)}
                          </button>
                        ))}
                        {editing && (
                          <button
                            type="button"
                            aria-label={`notify-test-${ev.key}`}
                            onClick={() => { setTestResult(null); test.mutate({ id: editing.id, event: ev.key }) }}
                            title={tr('notifications.testThisEvent')}
                            className="ml-1 rounded border border-slate-300 px-2 py-1 text-[11px] text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700"
                          >
                            {tr('notifications.testShort')}
                          </button>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
              {testResult && (creating || editing) && (
                <p
                  data-testid="notify-inline-test-result"
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

            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
                <input type="checkbox" aria-label="notify-digest" checked={form.digest_enabled} onChange={(e) => setForm({ ...form, digest_enabled: e.target.checked })} className="rounded" />
                {tr('notifications.fields.digest')}
              </label>
              <Field label={tr('notifications.fields.digestHour', { zone: localZone })}>
                <input
                  aria-label="notify-digest-hour"
                  type="number"
                  min={0}
                  max={23}
                  value={form.digest_hour}
                  onChange={(e) => setForm({ ...form, digest_hour: Number(e.target.value) })}
                  className={inputCls}
                />
              </Field>
            </div>

            <Field label={tr('notifications.fields.dashboardUrl')} hint={tr('notifications.fields.dashboardUrlHint')}>
              <input
                aria-label="notify-dashboard-url"
                value={form.dashboard_url}
                onChange={(e) => setForm({ ...form, dashboard_url: e.target.value })}
                className={inputCls}
                placeholder="https://npg.example.com"
              />
            </Field>

            {editing && (
              <button
                type="button"
                aria-label="notify-preview-digest"
                onClick={() => { setTestResult(null); test.mutate({ id: editing.id, event: 'digest.daily' }) }}
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
              >
                {tr('notifications.previewDigest')}
              </button>
            )}

            <Field label={tr('notifications.fields.language')} hint={tr('notifications.fields.languageHint')}>
              <select
                aria-label="notify-language"
                value={form.language}
                onChange={(e) => setForm({ ...form, language: e.target.value })}
                className={inputCls}
              >
                <option value="ko">한국어</option>
                <option value="en">English</option>
              </select>
            </Field>

            <label className="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200">
              <input
                type="checkbox"
                aria-label="notify-rich-format"
                checked={form.rich_format}
                onChange={(e) => setForm({ ...form, rich_format: e.target.checked })}
                className="mt-0.5 rounded"
              />
              <span>
                {tr('notifications.fields.richFormat')}
                <span className="mt-0.5 block text-xs text-slate-500 dark:text-slate-400">
                  {tr(`notifications.fields.richFormatHint.${form.type}`)}
                </span>
              </span>
            </label>

            <Field label={tr('notifications.fields.template')} hint={tr('notifications.fields.templateHint')}>
              <input aria-label="notify-template" value={form.template} onChange={(e) => setForm({ ...form, template: e.target.value })} className={inputCls} placeholder="{{event}} — {{host}} {{detail}}" />
            </Field>
            <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-900/40">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">{tr('notifications.placeholders')}</p>
              <p className="mt-1 flex flex-wrap gap-1">
                {TEMPLATE_PLACEHOLDERS.map((p) => (
                  <code key={p} className="rounded bg-white px-1.5 py-0.5 font-mono text-[11px] text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                    {`{{${p}}}`}
                  </code>
                ))}
              </p>
              <p data-testid="notify-pii-note" className="mt-2 text-[11px] text-amber-700 dark:text-amber-400">
                {tr('notifications.piiNote')}
              </p>
            </div>
          </div>
        </div>

        {/* The error lives beside Save, not at the top of the body. The form is
            two to three screens tall and Save is pinned, so an error rendered
            above the fold means clicking Save looks like nothing happened —
            which is exactly what a first Telegram attempt hits when the chat id
            is still blank. */}
        <div className="shrink-0 border-t border-slate-200 px-6 py-4 dark:border-slate-700">
          {formError && (
            <p data-testid="notification-form-error" className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
              {formError}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={close} className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {tr('common:buttons.cancel')}
            </button>
            {canWrite && (
              <button
                type="button"
                onClick={() => { setFormError(''); save.mutate(form) }}
                disabled={save.isPending}
                className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
              >
                {tr('common:buttons.save')}
              </button>
            )}
          </div>
        </div>
      </ModalShell>

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

const inputCls =
  'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-primary-500 focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-white'

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">{hint}</span>}
    </label>
  )
}

export default NotificationChannelManager

import type { NotificationChannel, NotificationChannelRequest } from '../../../types/notification'

/**
 * Pieces shared by the notification channel list and its form. They live here
 * rather than in either component because both need them and neither owns them.
 */

export const emptyForm = (): NotificationChannelRequest => ({
  name: '',
  type: 'webhook',
  enabled: true,
  config: {},
  events: [],
  digest_events: [],
  rich_format: true,
  // Defaults to the language the operator is configuring in: somebody
  // working in Korean does not expect English alerts.
  language: localStorage.getItem('npg_language') === 'ko' ? 'ko' : 'en',
  // Prefilled with the address the operator is looking at, which is almost
  // always the one they want in the message.
  dashboard_url: window.location.origin,
  digest_enabled: false,
  digest_hour: 9,
  allow_private_target: false,
  template: '',
})

export const toForm = (c: NotificationChannel): NotificationChannelRequest => ({
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

/** The browser's zone, used only to tell the operator when it DIFFERS from the
 *  server's. digest_hour is compared against the API container's clock, so the
 *  browser's zone is not the answer — labelling the field with it promised a
 *  9am summary to a Seoul operator whose container runs UTC. */
export const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'

/** Minutes the browser is offset from UTC, sign-matched to the server's. */
export const browserOffsetMinutes = -new Date().getTimezoneOffset()

export const fmt = (iso?: string) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

export const inputCls =
  'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-primary-500 focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-white'

/**
 * The server's validation messages are written for API clients: they name JSON
 * fields the form labels differently ("chat_id" vs Chat ID) and are only ever
 * English, which reads as a bug in an otherwise Korean panel. The code is the
 * stable part; an unrecognised one falls back to the raw message rather than
 * swallowing it.
 */
export function humanError(e: Error, tr: (k: string) => string) {
  const code = (e as { code?: string }).code
  if (code) {
    const key = `notifications.errors.${code}`
    const translated = tr(key)
    if (translated !== key) return translated
  }
  return e.message
}

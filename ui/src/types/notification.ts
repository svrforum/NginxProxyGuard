// Notification channel types (#221).

export type NotificationChannelType = 'webhook' | 'discord' | 'telegram'

/** One thing NPG can tell an operator about. Served by the API so the UI's
 *  checklist can never offer a key the server would reject. */
export interface NotificationEvent {
  key: string
  batched?: boolean
}

export interface NotificationChannel {
  id: string
  name: string
  type: NotificationChannelType
  enabled: boolean
  /** Credentials read back as the mask; send it unchanged to keep them. */
  config: Record<string, string>
  events: string[]
  digest_enabled: boolean
  digest_hour: number
  allow_private_target: boolean
  template: string
  last_success_at?: string
  last_error_at?: string
  last_error: string
  consecutive_failures: number
  created_at: string
  updated_at: string
}

export interface NotificationChannelRequest {
  name: string
  type: NotificationChannelType
  enabled: boolean
  config: Record<string, string>
  events: string[]
  digest_enabled: boolean
  digest_hour: number
  allow_private_target: boolean
  template: string
}

/** One delivery attempt, which is what answers "why did I not get an alert". */
export interface NotificationDelivery {
  id: number
  channel_id: string
  event_key: string
  status: 'queued' | 'sent' | 'failed' | 'dropped'
  attempts: number
  next_attempt_at: string
  last_error: string
  created_at: string
  sent_at?: string
  payload: { event: string; severity: string; text: string; fields: Record<string, string> }
}

export const NOTIFICATION_SECRET_PLACEHOLDER = '********'

/** The placeholders a template may use. Deliberately excludes request headers,
 *  cookies, raw log data, the user-agent and the request URI: those carry
 *  credentials and a notification leaves the operator's network. */
export const TEMPLATE_PLACEHOLDERS = [
  'event', 'time', 'host', 'ip', 'country', 'reason', 'count', 'detail', 'instance', 'subject',
] as const

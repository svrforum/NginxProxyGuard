import { apiGet, apiPost, apiPut, apiDelete } from './client'
import type {
  NotificationChannel,
  NotificationChannelRequest,
  NotificationDelivery,
  NotificationEvent,
  TelegramChat,
} from '../types/notification'

const API_BASE = '/api/v1'

/** The channel list, the event catalogue the server enforces, and the timezone
 *  the server actually schedules the digest in — which is the API container's,
 *  not the browser's. */
export async function listNotificationChannels(): Promise<{
  data: NotificationChannel[]
  events: NotificationEvent[]
  timezone?: { name: string; offset_minutes: number }
}> {
  return apiGet(`${API_BASE}/notification-channels`)
}

export async function createNotificationChannel(data: NotificationChannelRequest): Promise<NotificationChannel> {
  return apiPost(`${API_BASE}/notification-channels`, data)
}

export async function updateNotificationChannel(id: string, data: NotificationChannelRequest): Promise<NotificationChannel> {
  return apiPut(`${API_BASE}/notification-channels/${id}`, data)
}

export async function deleteNotificationChannel(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/notification-channels/${id}`)
}

/** Delivers immediately rather than queueing, so the button reports a real
 *  result instead of "accepted". */
/** eventKey lets the operator preview one specific alert rather than a generic
 *  "hello" — seeing the real shape is what makes the format choices meaningful. */
export async function testNotificationChannel(id: string, eventKey?: string): Promise<{ status: string }> {
  return apiPost(`${API_BASE}/notification-channels/${id}/test`, { event: eventKey ?? '' })
}

export async function listNotificationDeliveries(id: string): Promise<{ data: NotificationDelivery[] }> {
  return apiGet(`${API_BASE}/notification-channels/${id}/deliveries`)
}

/** Asks Telegram which conversations the bot can currently see. Telegram shows
 *  the chat id nowhere in its own interface, so without this the instruction
 *  would be "find your chat id" with no way to find it. */
export async function detectTelegramChats(botToken: string, channelId?: string): Promise<{ data: TelegramChat[] }> {
  return apiPost(`${API_BASE}/notification-channels/detect-telegram-chats`, {
    bot_token: botToken,
    channel_id: channelId ?? '',
  })
}

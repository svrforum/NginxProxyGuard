/**
 * The ban durations both screens offer, in seconds.
 *
 * One list, two places: adding a ban by hand and configuring Fail2ban's
 * automatic bans. They were separate before — a friendly dropdown on one screen
 * and a raw seconds box on the other — so the same concept looked like two
 * different settings, and the seconds box was capped at 7 days so 30 days could
 * not be expressed at all. (#252)
 *
 * Zero means permanent. That is the server's own convention: WAFAutoBanService
 * .banIP treats a duration of 0 as no expiry and sets is_permanent.
 */
export const BAN_DURATIONS = [
  { seconds: 300, key: '5m' },
  { seconds: 600, key: '10m' },
  { seconds: 1800, key: '30m' },
  { seconds: 3600, key: '1h' },
  { seconds: 86400, key: '24h' },
  { seconds: 604800, key: '7d' },
  { seconds: 2592000, key: '30d' },
  { seconds: 0, key: 'permanent' },
] as const

/** Sentinel for the "type a number of seconds" option in the Fail2ban form. */
export const CUSTOM_DURATION = -1

/** True when the value is not one of the offered durations, so the form should
 *  open on its free-text field rather than silently showing the wrong option. */
export function isCustomDuration(seconds: number): boolean {
  return !BAN_DURATIONS.some((d) => d.seconds === seconds)
}

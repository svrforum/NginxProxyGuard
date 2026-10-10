// Compile-time check that every Korean and English locale file has the same
// keys. Nothing imports this file: `tsc -b` type-checks everything under src,
// so the check runs in `npm run build`, the CI typecheck job and the Docker
// image build.
//
// Why: a key that exists only in ko/*.json falls back to Korean in the English
// UI (fallbackLng is 'ko'), as the WAF log detail button did in #321. A key
// that exists only in en/*.json shows the raw key in the Korean UI.
//
// Reading a failure: the error lands on the language that is missing the key,
// on the line of its namespace, and names the key ("Property 'viewAccessLog'
// is missing ..."). Add the key to that language's file.
import type { ALL_NAMESPACES } from './index'

// A and B have the same keys at every depth: each has to satisfy the other.
type Same<A extends B, B extends C, C = A> = [A, B]

export type LocaleParity = {
  common: Same<typeof import('./locales/ko/common.json'), typeof import('./locales/en/common.json')>
  navigation: Same<typeof import('./locales/ko/navigation.json'), typeof import('./locales/en/navigation.json')>
  auth: Same<typeof import('./locales/ko/auth.json'), typeof import('./locales/en/auth.json')>
  dashboard: Same<typeof import('./locales/ko/dashboard.json'), typeof import('./locales/en/dashboard.json')>
  accessControl: Same<typeof import('./locales/ko/accessControl.json'), typeof import('./locales/en/accessControl.json')>
  authProvider: Same<typeof import('./locales/ko/authProvider.json'), typeof import('./locales/en/authProvider.json')>
  proxyHost: Same<typeof import('./locales/ko/proxyHost.json'), typeof import('./locales/en/proxyHost.json')>
  settings: Same<typeof import('./locales/ko/settings.json'), typeof import('./locales/en/settings.json')>
  waf: Same<typeof import('./locales/ko/waf.json'), typeof import('./locales/en/waf.json')>
  logs: Same<typeof import('./locales/ko/logs.json'), typeof import('./locales/en/logs.json')>
  certificates: Same<typeof import('./locales/ko/certificates.json'), typeof import('./locales/en/certificates.json')>
  errors: Same<typeof import('./locales/ko/errors.json'), typeof import('./locales/en/errors.json')>
  redirectHost: Same<typeof import('./locales/ko/redirectHost.json'), typeof import('./locales/en/redirectHost.json')>
  exploitExceptions: Same<typeof import('./locales/ko/exploitExceptions.json'), typeof import('./locales/en/exploitExceptions.json')>
  exploitRules: Same<typeof import('./locales/ko/exploitRules.json'), typeof import('./locales/en/exploitRules.json')>
  fail2ban: Same<typeof import('./locales/ko/fail2ban.json'), typeof import('./locales/en/fail2ban.json')>
  exploitLogs: Same<typeof import('./locales/ko/exploitLogs.json'), typeof import('./locales/en/exploitLogs.json')>
  filterSubscription: Same<typeof import('./locales/ko/filterSubscription.json'), typeof import('./locales/en/filterSubscription.json')>
  ddns: Same<typeof import('./locales/ko/ddns.json'), typeof import('./locales/en/ddns.json')>
}

// A namespace added to ALL_NAMESPACES without a line above fails here, so a
// new namespace cannot slip past the check.
type Covers<T extends U, U> = T
export type EveryNamespaceChecked = Covers<LocaleParity, Record<(typeof ALL_NAMESPACES)[number], unknown>>

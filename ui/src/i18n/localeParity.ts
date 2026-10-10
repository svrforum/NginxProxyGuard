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
// is missing ..."). Add the key to that language's file. A missing plural is
// named by its base key: hostCount for hostCount_one and hostCount_other.
import type { ALL_NAMESPACES } from './index'

// A and B have the same keys at every depth: each has to satisfy the other.
type Same<A extends B, B extends C, C = A> = [A, B]

// Plural forms count as their base key. i18next keeps a plural as key_one,
// key_other and so on, and each language writes only the forms its grammar
// has: English needs hostCount_one and hostCount_other, Korean only
// hostCount_other. Comparing raw keys would demand a Korean _one that nothing
// reads. Folded, a plural still has to exist in both languages, and each
// language keeps its own forms. Ordinal forms (key_ordinal_one, ...) as well.
// Keys without an underscore, nearly all of them, skip the suffix matching,
// which keeps the check cheap.
type PluralForm = 'zero' | 'one' | 'two' | 'few' | 'many' | 'other'
type BaseKey<K> = K extends `${string}_${string}`
  ? K extends `${infer Base}_ordinal_${PluralForm}`
    ? Base
    : K extends `${infer Base}_${PluralForm}`
      ? Base
      : K
  : K

// A locale file's keys at every depth, with plural forms folded. Arrays (the
// step lists in settings) are compared as they are.
type Keys<T> = T extends readonly unknown[]
  ? T
  : T extends object
    ? { [K in keyof T as BaseKey<K>]: Keys<T[K]> }
    : T

export type LocaleParity = {
  common: Same<Keys<typeof import('./locales/ko/common.json')>, Keys<typeof import('./locales/en/common.json')>>
  navigation: Same<Keys<typeof import('./locales/ko/navigation.json')>, Keys<typeof import('./locales/en/navigation.json')>>
  auth: Same<Keys<typeof import('./locales/ko/auth.json')>, Keys<typeof import('./locales/en/auth.json')>>
  dashboard: Same<Keys<typeof import('./locales/ko/dashboard.json')>, Keys<typeof import('./locales/en/dashboard.json')>>
  accessControl: Same<Keys<typeof import('./locales/ko/accessControl.json')>, Keys<typeof import('./locales/en/accessControl.json')>>
  authProvider: Same<Keys<typeof import('./locales/ko/authProvider.json')>, Keys<typeof import('./locales/en/authProvider.json')>>
  proxyHost: Same<Keys<typeof import('./locales/ko/proxyHost.json')>, Keys<typeof import('./locales/en/proxyHost.json')>>
  settings: Same<Keys<typeof import('./locales/ko/settings.json')>, Keys<typeof import('./locales/en/settings.json')>>
  waf: Same<Keys<typeof import('./locales/ko/waf.json')>, Keys<typeof import('./locales/en/waf.json')>>
  logs: Same<Keys<typeof import('./locales/ko/logs.json')>, Keys<typeof import('./locales/en/logs.json')>>
  certificates: Same<Keys<typeof import('./locales/ko/certificates.json')>, Keys<typeof import('./locales/en/certificates.json')>>
  errors: Same<Keys<typeof import('./locales/ko/errors.json')>, Keys<typeof import('./locales/en/errors.json')>>
  redirectHost: Same<Keys<typeof import('./locales/ko/redirectHost.json')>, Keys<typeof import('./locales/en/redirectHost.json')>>
  exploitExceptions: Same<Keys<typeof import('./locales/ko/exploitExceptions.json')>, Keys<typeof import('./locales/en/exploitExceptions.json')>>
  exploitRules: Same<Keys<typeof import('./locales/ko/exploitRules.json')>, Keys<typeof import('./locales/en/exploitRules.json')>>
  fail2ban: Same<Keys<typeof import('./locales/ko/fail2ban.json')>, Keys<typeof import('./locales/en/fail2ban.json')>>
  exploitLogs: Same<Keys<typeof import('./locales/ko/exploitLogs.json')>, Keys<typeof import('./locales/en/exploitLogs.json')>>
  filterSubscription: Same<Keys<typeof import('./locales/ko/filterSubscription.json')>, Keys<typeof import('./locales/en/filterSubscription.json')>>
  ddns: Same<Keys<typeof import('./locales/ko/ddns.json')>, Keys<typeof import('./locales/en/ddns.json')>>
}

// A namespace added to ALL_NAMESPACES without a line above fails here, so a
// new namespace cannot slip past the check.
type Covers<T extends U, U> = T
export type EveryNamespaceChecked = Covers<LocaleParity, Record<(typeof ALL_NAMESPACES)[number], unknown>>

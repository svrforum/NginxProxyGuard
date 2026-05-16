import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

// Eagerly loaded namespaces — always required for the chrome (sidebar,
// top bar, login redirects). Everything else is fetched on first use so
// the initial bundle drops from ~32 JSON imports to 4.
import koCommon from './locales/ko/common.json'
import koNavigation from './locales/ko/navigation.json'
import enCommon from './locales/en/common.json'
import enNavigation from './locales/en/navigation.json'

export const STORAGE_KEY = 'npg_language'
export const SUPPORTED_LANGUAGES = ['ko', 'en'] as const
export type SupportedLanguage = typeof SUPPORTED_LANGUAGES[number]

export const LANGUAGE_NAMES: Record<SupportedLanguage, string> = {
  ko: '한국어',
  en: 'English',
}

const EAGER_NAMESPACES = ['common', 'navigation'] as const

// Every namespace that can be lazily loaded after first render. Kept as a
// literal array so the dynamic-import switch below has a closed set to
// match against (Vite's dynamic-import analysis works best with literal
// templates and reachable case branches).
const LAZY_NAMESPACES = [
  'auth',
  'dashboard',
  'accessControl',
  'proxyHost',
  'settings',
  'waf',
  'logs',
  'certificates',
  'errors',
  'redirectHost',
  'exploitExceptions',
  'exploitRules',
  'fail2ban',
  'exploitLogs',
  'filterSubscription',
] as const

export const ALL_NAMESPACES = [...EAGER_NAMESPACES, ...LAZY_NAMESPACES]

// Resources seeded at init() time — only the eager namespaces. Lazy
// namespaces arrive later via addResourceBundle from the backend below.
export const resources = {
  ko: {
    common: koCommon,
    navigation: koNavigation,
  },
  en: {
    common: enCommon,
    navigation: enNavigation,
  },
}

// loadLocaleNamespace dynamically imports a single JSON file. The two
// language switches let Vite resolve the import targets statically and
// emit one chunk per JSON, keeping each lazy load below ~64KB.
async function loadLocaleNamespace(lng: string, ns: string): Promise<Record<string, unknown>> {
  if (lng === 'ko') {
    return (await import(`./locales/ko/${ns}.json`)).default
  }
  if (lng === 'en') {
    return (await import(`./locales/en/${ns}.json`)).default
  }
  throw new Error(`unsupported locale: ${lng}`)
}

// Minimal i18next backend plugin. The `read` callback signature matches
// what i18next.services.backendConnector expects so loadNamespaces() and
// the automatic useTranslation trigger both work.
const dynamicBackend = {
  type: 'backend' as const,
  init: () => {},
  read(
    lng: string,
    ns: string,
    callback: (err: unknown, data?: Record<string, unknown>) => void,
  ) {
    loadLocaleNamespace(lng, ns).then(
      (data) => callback(null, data),
      (err) => callback(err),
    )
  },
}

i18n
  .use(dynamicBackend)
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    partialBundledLanguages: true,
    fallbackLng: 'ko',
    supportedLngs: SUPPORTED_LANGUAGES,
    defaultNS: 'common',
    ns: EAGER_NAMESPACES as unknown as string[],
    interpolation: {
      escapeValue: false, // React already escapes
    },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: STORAGE_KEY,
      caches: ['localStorage'],
    },
    react: {
      // Avoid suspending the entire app for a single namespace miss. The
      // backend still loads asynchronously, but useTranslation returns the
      // key as a placeholder until the namespace resolves and re-renders.
      useSuspense: false,
    },
  })

export default i18n

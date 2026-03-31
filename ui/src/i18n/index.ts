import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

// Korean translations
import koCommon from './locales/ko/common.json'
import koNavigation from './locales/ko/navigation.json'
import koAuth from './locales/ko/auth.json'
import koDashboard from './locales/ko/dashboard.json'
import koAccessControl from './locales/ko/accessControl.json'
import koProxyHost from './locales/ko/proxyHost.json'
import koSettings from './locales/ko/settings.json'
import koWaf from './locales/ko/waf.json'
import koLogs from './locales/ko/logs.json'
import koCertificates from './locales/ko/certificates.json'
import koErrors from './locales/ko/errors.json'
import koRedirectHost from './locales/ko/redirectHost.json'
import koExploitExceptions from './locales/ko/exploitExceptions.json'
import koExploitRules from './locales/ko/exploitRules.json'
import koFail2ban from './locales/ko/fail2ban.json'
import koExploitLogs from './locales/ko/exploitLogs.json'
import koFilterSubscription from './locales/ko/filterSubscription.json'


// English translations
import enCommon from './locales/en/common.json'
import enNavigation from './locales/en/navigation.json'
import enAuth from './locales/en/auth.json'
import enDashboard from './locales/en/dashboard.json'
import enAccessControl from './locales/en/accessControl.json'
import enProxyHost from './locales/en/proxyHost.json'
import enSettings from './locales/en/settings.json'
import enWaf from './locales/en/waf.json'
import enLogs from './locales/en/logs.json'
import enCertificates from './locales/en/certificates.json'
import enErrors from './locales/en/errors.json'
import enRedirectHost from './locales/en/redirectHost.json'
import enExploitExceptions from './locales/en/exploitExceptions.json'
import enExploitRules from './locales/en/exploitRules.json'
import enFail2ban from './locales/en/fail2ban.json'
import enExploitLogs from './locales/en/exploitLogs.json'
import enFilterSubscription from './locales/en/filterSubscription.json'


export const STORAGE_KEY = 'npg_language'
export const SUPPORTED_LANGUAGES = ['ko', 'en'] as const
export type SupportedLanguage = typeof SUPPORTED_LANGUAGES[number]

export const LANGUAGE_NAMES: Record<SupportedLanguage, string> = {
  ko: '한국어',
  en: 'English',
}

export const resources = {
  ko: {
    common: koCommon,
    navigation: koNavigation,
    auth: koAuth,
    dashboard: koDashboard,
    accessControl: koAccessControl,
    proxyHost: koProxyHost,
    settings: koSettings,
    waf: koWaf,
    logs: koLogs,
    certificates: koCertificates,
    errors: koErrors,
    redirectHost: koRedirectHost,
    exploitExceptions: koExploitExceptions,
    exploitRules: koExploitRules,
    fail2ban: koFail2ban,
    exploitLogs: koExploitLogs,
    filterSubscription: koFilterSubscription,
  },
  en: {
    common: enCommon,
    navigation: enNavigation,
    auth: enAuth,
    dashboard: enDashboard,
    accessControl: enAccessControl,
    proxyHost: enProxyHost,
    settings: enSettings,
    waf: enWaf,
    logs: enLogs,
    certificates: enCertificates,
    errors: enErrors,
    redirectHost: enRedirectHost,
    exploitExceptions: enExploitExceptions,
    exploitRules: enExploitRules,
    fail2ban: enFail2ban,
    exploitLogs: enExploitLogs,
    filterSubscription: enFilterSubscription,
  },
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'ko',
    supportedLngs: SUPPORTED_LANGUAGES,
    defaultNS: 'common',
    ns: [
      'common',
      'navigation',
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
    ],
    interpolation: {
      escapeValue: false, // React already escapes
    },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: STORAGE_KEY,
      caches: ['localStorage'],
    },
  })

export default i18n

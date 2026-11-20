import { useTranslation } from 'react-i18next'
import { useLanguage } from '../i18n/hooks/useLanguage'
import type { SupportedLanguage } from '../i18n'

interface LanguageSwitcherProps {
  variant?: 'dropdown' | 'buttons' | 'select'
  className?: string
}

export function LanguageSwitcher({ variant = 'select', className = '' }: LanguageSwitcherProps) {
  const { currentLanguage, changeLanguage, isChanging, supportedLanguages, languageNames } = useLanguage()
  const { t } = useTranslation('common')

  if (variant === 'buttons') {
    return (
      <div className={`flex gap-1 ${className}`}>
        {supportedLanguages.map((lang) => (
          <button
            key={lang}
            onClick={() => changeLanguage(lang)}
            disabled={isChanging || currentLanguage === lang}
            className={`px-3 py-1.5 text-sm font-medium rounded-lg transition-colors ${
              currentLanguage === lang
                ? 'bg-primary-600 text-white'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            } disabled:opacity-50`}
          >
            {languageNames[lang]}
          </button>
        ))}
      </div>
    )
  }

  if (variant === 'dropdown') {
    return (
      <div className={`relative ${className}`}>
        <select
          value={currentLanguage}
          onChange={(e) => changeLanguage(e.target.value as SupportedLanguage)}
          disabled={isChanging}
          aria-label={t('labels.language')}
          className="appearance-none bg-transparent text-sm font-medium text-slate-200 hover:text-white [&>option]:text-slate-900 cursor-pointer pr-6 py-1 disabled:opacity-50"
        >
          {supportedLanguages.map((lang) => (
            <option key={lang} value={lang}>
              {languageNames[lang]}
            </option>
          ))}
        </select>
        <svg
          className="absolute right-0 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    )
  }

  // Default: select variant with full styling
  return (
    <div className={className}>
      <select
        value={currentLanguage}
        onChange={(e) => changeLanguage(e.target.value as SupportedLanguage)}
        disabled={isChanging}
        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 disabled:opacity-50"
      >
        {supportedLanguages.map((lang) => (
          <option key={lang} value={lang}>
            {languageNames[lang]}
          </option>
        ))}
      </select>
    </div>
  )
}

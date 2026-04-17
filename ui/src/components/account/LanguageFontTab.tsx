import { useTranslation } from 'react-i18next';

// Font family options (shared with AccountSettings)
export const FONT_OPTIONS = [
  { value: 'system', label: 'System Default', labelKo: '시스템 기본' },
  { value: 'gowun-batang', label: 'Gowun Batang', labelKo: '고운 바탕' },
  { value: 'noto-sans-kr', label: 'Noto Sans KR', labelKo: 'Noto Sans KR' },
  { value: 'pretendard', label: 'Pretendard', labelKo: 'Pretendard' },
  { value: 'inter', label: 'Inter', labelKo: 'Inter' },
];

interface LanguageFontTabProps {
  currentLanguage: string;
  supportedLanguages: readonly string[];
  languageNames: Record<string, string>;
  changeLanguage: (lang: 'ko' | 'en') => void;
  currentFontFamily: string;
  changingFont: boolean;
  onFontFamilyChange: (fontFamily: string) => Promise<void>;
}

export function LanguageFontTab({
  currentLanguage,
  supportedLanguages,
  languageNames,
  changeLanguage,
  currentFontFamily,
  changingFont,
  onFontFamilyChange,
}: LanguageFontTabProps) {
  const { t } = useTranslation(['auth', 'navigation']);

  return (
    <>
      <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
        <p className="text-gray-500 dark:text-gray-400 text-sm">{t('navigation:account.language')}</p>
        <select
          value={currentLanguage}
          onChange={(e) => changeLanguage(e.target.value as 'ko' | 'en')}
          className="mt-1 w-full px-3 py-1.5 bg-white dark:bg-gray-600 border border-gray-300 dark:border-gray-500 rounded text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:outline-none"
        >
          {supportedLanguages.map((lang) => (
            <option key={lang} value={lang}>
              {languageNames[lang]}
            </option>
          ))}
        </select>
      </div>
      <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
        <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.fontFamily', '폰트')}</p>
        <select
          value={currentFontFamily}
          onChange={(e) => onFontFamilyChange(e.target.value)}
          disabled={changingFont}
          className="mt-1 w-full px-3 py-1.5 bg-white dark:bg-gray-600 border border-gray-300 dark:border-gray-500 rounded text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:outline-none disabled:opacity-50"
        >
          {FONT_OPTIONS.map((font) => (
            <option key={font.value} value={font.value}>
              {currentLanguage === 'ko' ? font.labelKo : font.label}
            </option>
          ))}
        </select>
      </div>
    </>
  );
}

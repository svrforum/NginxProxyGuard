import { useTranslation } from 'react-i18next'
import type { CertificateKeyType } from '../../types/certificate'
import { HelpTip } from '../common/HelpTip'

const KEY_TYPES: CertificateKeyType[] = ['rsa2048', 'ec256', 'ec384']

interface KeyTypeSelectProps {
  value?: CertificateKeyType
  onChange: (keyType: CertificateKeyType) => void
  // The proxy host form's smaller field style.
  compact?: boolean
}

// The key type a new Let's Encrypt certificate is issued with (#364).
export function KeyTypeSelect({ value, onChange, compact = false }: KeyTypeSelectProps) {
  const { t } = useTranslation('certificates')
  return (
    <div>
      <label
        className={
          compact
            ? 'block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-2'
            : 'block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2'
        }
      >
        {t('form.keyType')}
        <HelpTip contentKey="help.keyType" ns="certificates" />
      </label>
      <select
        value={value ?? 'rsa2048'}
        onChange={(e) => onChange(e.target.value as CertificateKeyType)}
        className={`w-full rounded-lg border border-slate-300 dark:border-slate-600 ${compact ? 'px-3 py-2' : 'px-4 py-2.5'} text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white`}
      >
        {KEY_TYPES.map((keyType) => (
          <option key={keyType} value={keyType}>
            {t(`keyTypes.${keyType}`)}
            {keyType === 'rsa2048' ? t('form.defaultSuffix') : ''}
          </option>
        ))}
      </select>
    </div>
  )
}

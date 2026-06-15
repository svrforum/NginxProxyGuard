import type { GeoDataState } from '../../types'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'

interface PriorityAllowIPsProps {
  allowedIPsInput: string
  setAllowedIPsInput: (value: string) => void
  geoData: GeoDataState
  setGeoData: React.Dispatch<React.SetStateAction<GeoDataState>>
}

export function PriorityAllowIPs({
  allowedIPsInput,
  setAllowedIPsInput,
  geoData,
  setGeoData,
}: PriorityAllowIPsProps) {
  const { t } = useTranslation('proxyHost')
  return (
    <div className="p-4 rounded-lg border-2 border-blue-200 bg-blue-50 dark:bg-blue-900/10 dark:border-blue-800 transition-colors">
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-full flex items-center justify-center bg-blue-100 dark:bg-blue-900/30 flex-shrink-0">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
              {t('form.security.priorityAllowIPs.title')}
              <HelpTip contentKey="help.security.priorityAllowIPs" />
            </span>
            <span className="px-1.5 py-0.5 text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 rounded">{t('form.security.priorityAllowIPs.overrideTag')}</span>
          </div>
          <p className="text-xs text-slate-600 dark:text-slate-400 mb-3">
            {t('form.security.priorityAllowIPs.description')}
          </p>
          <textarea
            value={allowedIPsInput}
            onChange={(e) => {
              setAllowedIPsInput(e.target.value)
              const ips = e.target.value
                .split('\n')
                .map((ip) => ip.trim())
                .filter((ip) => ip.length > 0)
              setGeoData((prev) => ({ ...prev, allowed_ips: ips }))
            }}
            placeholder={t('form.security.priorityAllowIPs.placeholder')}
            rows={3}
            className="w-full rounded-lg border border-blue-300 dark:border-blue-700 px-3 py-2 text-sm font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
          />
          <div className="mt-2 flex items-start gap-2">
            <svg className="w-4 h-4 text-blue-500 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-xs text-blue-600 dark:text-blue-400">
              {t('form.security.priorityAllowIPs.note')}
              {geoData.allowed_ips && geoData.allowed_ips.length > 0 && (
                <span className="ml-1 font-medium">({t('form.security.priorityAllowIPs.registeredCount', { count: geoData.allowed_ips.length })})</span>
              )}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

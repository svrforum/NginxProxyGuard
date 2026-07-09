import type { CreateSecurityHeadersRequest } from '../../../../types/security'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'

/**
 * The security-headers option fields (HSTS, X-Frame-Options, Referrer-Policy,
 * X-Content-Type-Options, X-XSS-Protection), shared by the per-host section
 * (override mode) and the GlobalSecurityHeadersManager. Generic over any state
 * extending CreateSecurityHeadersRequest so both drive it. The enable/inherit
 * wrapper is the parent's responsibility.
 */
interface SecurityHeadersFieldsProps<T extends CreateSecurityHeadersRequest> {
  data: T
  setData: React.Dispatch<React.SetStateAction<T>>
}

export function SecurityHeadersFields<T extends CreateSecurityHeadersRequest>({
  data,
  setData,
}: SecurityHeadersFieldsProps<T>) {
  const { t } = useTranslation(['proxyHost', 'common'])

  return (
    <div className="space-y-4">
      {/* HSTS Settings */}
      <div className="p-3 bg-white dark:bg-slate-800 rounded-lg space-y-2">
        <div className="flex items-center gap-1">
          <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{t('form.protection.securityHeaders.hsts')}</span>
          <HelpTip contentKey="help.protection.securityHeadersDetail.hsts" />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={data.hsts_enabled ?? false}
              onChange={(e) => setData((prev) => ({ ...prev, hsts_enabled: e.target.checked }))}
              className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
            />
            <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.hstsEnabled')}</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={data.hsts_include_subdomains ?? false}
              onChange={(e) => setData((prev) => ({ ...prev, hsts_include_subdomains: e.target.checked }))}
              className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
            />
            <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.includeSubdomains')}</span>
            <HelpTip contentKey="help.protection.securityHeadersDetail.includeSubdomains" />
          </label>
        </div>
      </div>

      {/* X-Frame-Options and Referrer Policy */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="flex items-center gap-1 text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('form.protection.securityHeaders.xFrameOptions')}
            <HelpTip contentKey="help.protection.securityHeadersDetail.xFrameOptions" />
          </label>
          <select
            value={data.x_frame_options ?? 'SAMEORIGIN'}
            onChange={(e) => setData((prev) => ({ ...prev, x_frame_options: e.target.value }))}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="DENY">DENY</option>
            <option value="SAMEORIGIN">SAMEORIGIN</option>
            <option value="">{t('common:misc.none')}</option>
          </select>
        </div>
        <div>
          <label className="flex items-center gap-1 text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('form.protection.securityHeaders.referrerPolicy')}
            <HelpTip contentKey="help.protection.securityHeadersDetail.referrerPolicy" />
          </label>
          <select
            value={data.referrer_policy ?? 'strict-origin-when-cross-origin'}
            onChange={(e) => setData((prev) => ({ ...prev, referrer_policy: e.target.value }))}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="no-referrer">no-referrer</option>
            <option value="strict-origin">strict-origin</option>
            <option value="strict-origin-when-cross-origin">strict-origin-when-cross-origin</option>
          </select>
        </div>
      </div>

      {/* Additional Checkboxes */}
      <div className="space-y-2">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={data.x_content_type_options ?? false}
            onChange={(e) => setData((prev) => ({ ...prev, x_content_type_options: e.target.checked }))}
            className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
          />
          <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.xContentType')}</span>
          <HelpTip contentKey="help.protection.securityHeadersDetail.xContentType" />
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={data.x_xss_protection ?? false}
            onChange={(e) => setData((prev) => ({ ...prev, x_xss_protection: e.target.checked }))}
            className="rounded border-slate-300 dark:border-slate-600 text-blue-600 dark:bg-slate-700"
          />
          <span className="text-xs text-slate-900 dark:text-slate-300">{t('form.protection.securityHeaders.xssProtection')}</span>
          <HelpTip contentKey="help.protection.securityHeadersDetail.xssProtection" />
        </label>
      </div>

      {/* Advanced Headers Notice */}
      <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
        <div className="flex items-start gap-2">
          <svg className="w-4 h-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div>
            <p className="text-xs font-medium text-amber-800 dark:text-amber-300">{t('form.protection.securityHeaders.advancedHeadersTitle')}</p>
            <p className="text-xs text-amber-700 dark:text-amber-400 mt-1">{t('form.protection.securityHeaders.advancedHeadersDesc')}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

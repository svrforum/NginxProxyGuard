import { useId } from 'react'
import { useTranslation } from 'react-i18next'
import { DnsHostnamesField, type DnsListDomains } from '../../../common/dns/DnsHostnamesField'

// The value fields shared by the per-host rate limit and the global default.
// The nginx limit_req zone name is derived per-host server-side, so it is not
// part of the editable field set here.
export interface RateLimitFieldValues {
  requests_per_second: number
  burst_size: number
  limit_by: string
  limit_response: number
  whitelist_ips: string
  // Domains exempt like whitelist_ips (#320).
  whitelist_hostnames: string[]
}

interface RateLimitFieldsProps {
  values: RateLimitFieldValues
  onChange: (patch: Partial<RateLimitFieldValues>) => void
  /** The exception domains' state, permission and confirm route, from the screen that saves them. */
  domains: DnsListDomains
}

/**
 * The editable rate-limit fields (requests/s, burst, limit-by, response code,
 * whitelist IPs and domains). Shared between the per-host override
 * (ProtectionTab) and the global default manager so both stay in lock-step
 * (#198 slice 5).
 */
export function RateLimitFields({ values, onChange, domains }: RateLimitFieldsProps) {
  const { t } = useTranslation(['proxyHost', 'dnsEntries'])
  const fid = useId()

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label htmlFor={`${fid}-rate-1`} className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.requestsPerSecond')}</label>
          <input
            id={`${fid}-rate-1`}
            type="number"
            value={values.requests_per_second}
            onChange={(e) => onChange({ requests_per_second: Number(e.target.value) })}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-primary-500 transition-colors bg-white dark:bg-slate-700 dark:text-white"
          />
        </div>
        <div>
          <label htmlFor={`${fid}-rate-2`} className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.burst')}</label>
          <input
            id={`${fid}-rate-2`}
            type="number"
            value={values.burst_size}
            onChange={(e) => onChange({ burst_size: Number(e.target.value) })}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-primary-500 transition-colors bg-white dark:bg-slate-700 dark:text-white"
          />
        </div>
        <div>
          <label htmlFor={`${fid}-rate-3`} className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.limitBy')}</label>
          <select
            id={`${fid}-rate-3`}
            value={values.limit_by}
            onChange={(e) => onChange({ limit_by: e.target.value })}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-primary-500 transition-colors bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value="ip">{t('form.protection.rateLimit.limitByOptions.ip')}</option>
            <option value="uri">{t('form.protection.rateLimit.limitByOptions.uri')}</option>
            <option value="ip_uri">{t('form.protection.rateLimit.limitByOptions.ipUri')}</option>
          </select>
        </div>
        <div>
          <label htmlFor={`${fid}-rate-4`} className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.responseCode')}</label>
          <select
            id={`${fid}-rate-4`}
            value={values.limit_response}
            onChange={(e) => onChange({ limit_response: Number(e.target.value) })}
            className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-primary-500 transition-colors bg-white dark:bg-slate-700 dark:text-white"
          >
            <option value={429}>429 Too Many Requests</option>
            <option value={503}>503 Service Unavailable</option>
          </select>
        </div>
      </div>

      <div>
        <label htmlFor={`${fid}-rate-5`} className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">{t('form.protection.rateLimit.whitelistIPs')}</label>
        <input
          id={`${fid}-rate-5`}
          type="text"
          value={values.whitelist_ips}
          onChange={(e) => onChange({ whitelist_ips: e.target.value })}
          placeholder="192.168.1.1, 10.0.0.0/8"
          className="w-full px-3 py-2 text-sm border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-primary-500 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
        />
      </div>

      <DnsHostnamesField
        {...domains}
        names={values.whitelist_hostnames}
        onChange={(names) => onChange({ whitelist_hostnames: names })}
        note={t('dnsEntries:notes.rateLimit')}
      />
    </div>
  )
}

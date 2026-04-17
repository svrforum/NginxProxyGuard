import { useTranslation } from 'react-i18next';
import type { Log } from '../../../types/log';
import { LogTypeBadge } from '../badges';

interface LogDetailHeaderProps {
  log: Log;
  onClose: () => void;
  onBanClick: () => void;
}

export function LogDetailHeader({ log, onClose, onBanClick }: LogDetailHeaderProps) {
  const { t, i18n } = useTranslation('logs');

  return (
    <>
      <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <LogTypeBadge type={log.log_type} />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('detail.title')}</h2>
        </div>
        <button
          onClick={onClose}
          className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
        >
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4 px-4 pt-4">
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.timestamp')}</label>
          <p className="text-sm text-slate-900 dark:text-white">{new Date(log.timestamp).toLocaleString(i18n.language)}</p>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.clientIP')}</label>
          <div className="flex items-center gap-2">
            {log.client_ip ? (
              <button
                onClick={onBanClick}
                className="group flex items-center gap-2 px-2 py-1 -ml-2 text-sm font-mono text-slate-900 dark:text-white hover:bg-red-50 dark:hover:bg-red-900/30 hover:text-red-700 dark:hover:text-red-400 rounded-lg transition-colors"
                title={t('banIP.clickToBan')}
              >
                <span>{log.client_ip}</span>
                <svg className="w-4 h-4 text-red-500 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              </button>
            ) : (
              <p className="text-sm text-slate-900 dark:text-white font-mono">-</p>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// GeoIP section - shared presentation
export function LogDetailGeoIP({ log }: { log: Log }) {
  const { t } = useTranslation('logs');
  if (!log.geo_country_code) return null;
  return (
    <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
      <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-2 block">{t('detail.geoIp')}</label>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div>
          <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.country')}</span>
          <p className="text-sm text-slate-900 dark:text-white flex items-center gap-1">
            <span className="text-base">
              {log.geo_country_code
                .toUpperCase()
                .split('')
                .map(char => String.fromCodePoint(127397 + char.charCodeAt(0)))
                .join('')}
            </span>
            {log.geo_country || log.geo_country_code}
          </p>
        </div>
        {log.geo_city && (
          <div>
            <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.city')}</span>
            <p className="text-sm text-slate-900 dark:text-white">{log.geo_city}</p>
          </div>
        )}
        {log.geo_asn && (
          <div>
            <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.asn')}</span>
            <p className="text-sm text-slate-900 dark:text-white font-mono">{log.geo_asn}</p>
          </div>
        )}
        {log.geo_org && (
          <div className="col-span-2 md:col-span-1">
            <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.org')}</span>
            <p className="text-sm text-slate-900 dark:text-white truncate" title={log.geo_org}>{log.geo_org}</p>
          </div>
        )}
      </div>
    </div>
  );
}

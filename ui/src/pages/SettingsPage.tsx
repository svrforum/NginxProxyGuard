import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import GlobalSettings from '../components/GlobalSettings'
import ChallengeSettings from '../components/ChallengeSettings'
import GeoIPSettings from '../components/GeoIPSettings'
import SSLACMESettings from '../components/SSLACMESettings'
import MaintenanceSettings from '../components/MaintenanceSettings'
import BackupManager from '../components/BackupManager'
import BotFilterSettings from '../components/BotFilterSettings'
import WAFAutoBanSettings from '../components/WAFAutoBanSettings'
import SystemLogSettings from '../components/SystemLogSettings'
import FilterSubscriptionList from '../components/FilterSubscriptionList'

export default function SettingsPage({ subTab }: { subTab: 'global' | 'captcha' | 'geoip' | 'ssl' | 'maintenance' | 'backups' | 'botfilter' | 'waf-auto-ban' | 'system-logs' | 'filter-subscriptions' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for settings */}
      <div className="border-b border-slate-200">
        <div className="flex gap-4 overflow-x-auto">
          <button
            onClick={() => navigate('/settings/global')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'global'
              ? 'border-teal-600 text-teal-600 dark:text-teal-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.global')}
          </button>
          <button
            onClick={() => navigate('/settings/captcha')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'captcha'
              ? 'border-blue-600 text-blue-600 dark:text-blue-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.captcha')}
          </button>
          <button
            onClick={() => navigate('/settings/geoip')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'geoip'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.geoip')}
          </button>
          <button
            onClick={() => navigate('/settings/botfilter')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'botfilter'
              ? 'border-orange-600 text-orange-600 dark:text-orange-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.botfilter')}
          </button>
          <button
            onClick={() => navigate('/settings/waf-auto-ban')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'waf-auto-ban'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.wafAutoBan')}
          </button>
          <button
            onClick={() => navigate('/settings/ssl')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'ssl'
              ? 'border-amber-600 text-amber-600 dark:text-amber-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.ssl')}
          </button>
          <button
            onClick={() => navigate('/settings/maintenance')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'maintenance'
              ? 'border-purple-600 text-purple-600 dark:text-purple-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.maintenance')}
          </button>
          <button
            onClick={() => navigate('/settings/backups')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'backups'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.backups')}
          </button>
          <button
            onClick={() => navigate('/settings/system-logs')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'system-logs'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.systemLogs', 'System Logs')}
          </button>
          <button
            onClick={() => navigate('/settings/filter-subscriptions')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'filter-subscriptions'
              ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.settings.filterSubscriptions', 'Filter Subscriptions')}
          </button>
        </div>
      </div>

      {subTab === 'global' && <GlobalSettings />}
      {subTab === 'captcha' && <ChallengeSettings />}
      {subTab === 'geoip' && <GeoIPSettings />}
      {subTab === 'botfilter' && <BotFilterSettings />}
      {subTab === 'waf-auto-ban' && <WAFAutoBanSettings />}
      {subTab === 'ssl' && <SSLACMESettings />}
      {subTab === 'maintenance' && <MaintenanceSettings />}
      {subTab === 'backups' && <BackupManager />}
      {subTab === 'system-logs' && <SystemLogSettings />}
      {subTab === 'filter-subscriptions' && <FilterSubscriptionList />}
    </div>
  )
}

import { Fragment } from 'react'
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

type SubTab =
  | 'global'
  | 'captcha'
  | 'geoip'
  | 'ssl'
  | 'maintenance'
  | 'backups'
  | 'botfilter'
  | 'waf-auto-ban'
  | 'system-logs'
  | 'filter-subscriptions'

export default function SettingsPage({ subTab }: { subTab: SubTab }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  // Horizontal sub-tabs (consistent with the other areas) but reordered into
  // three logical groups separated by dividers, with a single primary accent
  // color instead of the previous flat, rainbow-colored row.
  const groups: { label: string; items: { key: SubTab; label: string }[] }[] = [
    {
      label: t('subTabs.settings.groups.general'),
      items: [
        { key: 'global', label: t('subTabs.settings.global') },
        { key: 'ssl', label: t('subTabs.settings.ssl') },
      ],
    },
    {
      label: t('subTabs.settings.groups.security'),
      items: [
        { key: 'captcha', label: t('subTabs.settings.captcha') },
        { key: 'geoip', label: t('subTabs.settings.geoip') },
        { key: 'botfilter', label: t('subTabs.settings.botfilter') },
        { key: 'waf-auto-ban', label: t('subTabs.settings.wafAutoBan') },
        { key: 'filter-subscriptions', label: t('subTabs.settings.filterSubscriptions') },
      ],
    },
    {
      label: t('subTabs.settings.groups.operations'),
      items: [
        { key: 'maintenance', label: t('subTabs.settings.maintenance') },
        { key: 'backups', label: t('subTabs.settings.backups') },
        { key: 'system-logs', label: t('subTabs.settings.systemLogs') },
      ],
    },
  ]

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-200 dark:border-slate-700">
        <div className="flex items-stretch gap-1 overflow-x-auto">
          {groups.map((group, gi) => (
            <Fragment key={group.label}>
              {gi > 0 && (
                <span aria-hidden className="mx-2 my-2 w-px self-stretch bg-slate-200 dark:bg-slate-700" />
              )}
              <div role="group" aria-label={group.label} className="flex items-stretch gap-1">
                {group.items.map((item) => {
                  const active = subTab === item.key
                  return (
                    <button
                      key={item.key}
                      onClick={() => navigate(`/settings/${item.key}`)}
                      aria-current={active ? 'page' : undefined}
                      className={`whitespace-nowrap border-b-2 px-3 pb-2 text-[13px] font-semibold transition-colors ${
                        active
                          ? 'border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400'
                          : 'border-transparent text-slate-600 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
                      }`}
                    >
                      {item.label}
                    </button>
                  )
                })}
              </div>
            </Fragment>
          ))}
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

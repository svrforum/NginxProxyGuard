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
import CloudflareTunnelSettings from '../components/settings/CloudflareTunnelSettings'
import RoleManager from '../components/settings/RoleManager'
import SSOProviderManager from '../components/settings/SSOProviderManager'
import UserManager from '../components/settings/UserManager'
import { usePermissions } from '../hooks/usePermissions'

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
  | 'cloudflare-tunnel'
  | 'users'
  | 'roles'
  | 'sso'

export default function SettingsPage({ subTab }: { subTab: SubTab }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()
  // Sub-tabs the caller has no permission for are hidden. Convenience only —
  // the server refuses the underlying endpoints regardless. (#222)
  const { canArea } = usePermissions()

  // Horizontal sub-tabs (consistent with the other areas) but reordered into
  // three logical groups separated by dividers, with a single primary accent
  // color instead of the previous flat, rainbow-colored row.
  const groups: { label: string; items: { key: SubTab; label: string }[] }[] = [
    {
      label: t('subTabs.settings.groups.general'),
      items: canArea('settings')
        ? [
          { key: 'global' as SubTab, label: t('subTabs.settings.global') },
          { key: 'ssl' as SubTab, label: t('subTabs.settings.ssl') },
        ]
        : [],
    },
    {
      label: t('subTabs.settings.groups.security'),
      items: canArea('settings')
        ? [
          { key: 'captcha' as SubTab, label: t('subTabs.settings.captcha') },
          { key: 'geoip' as SubTab, label: t('subTabs.settings.geoip') },
          { key: 'botfilter' as SubTab, label: t('subTabs.settings.botfilter') },
          { key: 'waf-auto-ban' as SubTab, label: t('subTabs.settings.wafAutoBan') },
          { key: 'filter-subscriptions' as SubTab, label: t('subTabs.settings.filterSubscriptions') },
        ]
        : [],
    },
    {
      label: t('subTabs.settings.groups.access'),
      items: [
        ...(canArea('user') ? [{ key: 'users' as SubTab, label: t('subTabs.settings.users') }] : []),
        ...(canArea('role') ? [{ key: 'roles' as SubTab, label: t('subTabs.settings.roles') }] : []),
        ...(canArea('settings') ? [{ key: 'sso' as SubTab, label: t('subTabs.settings.sso') }] : []),
      ],
    },
    {
      label: t('subTabs.settings.groups.operations'),
      items: [
        ...(canArea('settings') ? [{ key: 'maintenance' as SubTab, label: t('subTabs.settings.maintenance') }] : []),
        ...(canArea('backup') ? [{ key: 'backups' as SubTab, label: t('subTabs.settings.backups') }] : []),
        ...(canArea('settings')
          ? [
            { key: 'system-logs' as SubTab, label: t('subTabs.settings.systemLogs') },
            { key: 'cloudflare-tunnel' as SubTab, label: t('subTabs.settings.cloudflareTunnel') },
          ]
          : []),
      ],
    },
  ]

  const visibleGroups = groups.filter((g) => g.items.length > 0)
  const visibleKeys = new Set(visibleGroups.flatMap((g) => g.items.map((i) => i.key)))

  // Reaching a settings sub-tab the role cannot use (a bookmark, a typed URL)
  // would otherwise render a full tab bar whose every request 403s. Say so
  // instead. The server is what actually refuses; this is just honest UI.
  if (!visibleKeys.has(subTab)) {
    return (
      <div className="rounded-lg border border-slate-200 bg-white p-8 text-center dark:border-slate-700 dark:bg-slate-800">
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">{t('noPermission.title')}</p>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('noPermission.hint')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-200 dark:border-slate-700">
        <div className="flex items-stretch gap-1 overflow-x-auto">
          {visibleGroups.map((group, gi) => (
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
      {subTab === 'cloudflare-tunnel' && <CloudflareTunnelSettings />}
      {subTab === 'users' && <UserManager />}
      {subTab === 'roles' && <RoleManager />}
      {subTab === 'sso' && <SSOProviderManager />}
    </div>
  )
}

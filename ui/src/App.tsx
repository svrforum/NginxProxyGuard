import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import ErrorBoundary from './components/ErrorBoundary'
import { ProxyHostList } from './components/ProxyHostList'
import { ProxyHostForm } from './components/ProxyHostForm'
import CertificateList from './components/CertificateList'
import CertificateHistoryList from './components/CertificateHistory'
import DNSProviderList from './components/DNSProviderList'
import { LogViewer } from './components/LogViewer'
import { SystemLogViewer } from './components/SystemLogViewer'
import AuditLog from './components/AuditLog'
import { WAFTester } from './components/WAFTester'
import { WAFSettings } from './components/WAFSettings'
import { ExploitBlockRules } from './components/ExploitBlockRules'
import { Fail2banManagement } from './components/Fail2banManagement'
import AccessListManager from './components/AccessListManager'
import { BannedIPList } from './components/BannedIPList'
import { URIBlockManager } from './components/URIBlockManager'
import RedirectHostManager from './components/RedirectHostManager'
import Dashboard from './components/Dashboard'
import GlobalSettings from './components/GlobalSettings'
import ChallengeSettings from './components/ChallengeSettings'
import GeoIPSettings from './components/GeoIPSettings'
import SSLACMESettings from './components/SSLACMESettings'
import MaintenanceSettings from './components/MaintenanceSettings'
import BackupManager from './components/BackupManager'
import RawLogFiles from './components/RawLogFiles'
import BotFilterSettings from './components/BotFilterSettings'
import BotFilterLogs from './components/BotFilterLogs'
import ExploitBlockLogs from './components/ExploitBlockLogs'
import WAFAutoBanSettings from './components/WAFAutoBanSettings'
import SystemLogSettings from './components/SystemLogSettings'
import { Login } from './components/Login'
import { InitialSetup } from './components/InitialSetup'
import AccountSettings from './components/AccountSettings'
import { getAuthStatus, logout, getToken, User } from './api/auth'
import { apiPost } from './api/client'
import type { ProxyHost } from './types/proxy-host'
import { useDarkMode } from './hooks/useDarkMode'

interface HealthResponse {
  status: string
  version: string
  database: string
}

async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch('/health')
  if (!res.ok) throw new Error('Health check failed')
  return res.json()
}


type Tab = 'dashboard' | 'proxy-hosts' | 'redirects' | 'waf' | 'access' | 'certificates' | 'logs' | 'settings'

interface AppContentProps {
  user: User
  onLogout: () => void
}

function AppContent({ user, onLogout }: AppContentProps) {
  const { t } = useTranslation(['navigation', 'common'])
  const navigate = useNavigate()
  const location = useLocation()
  const { isDark, toggle } = useDarkMode()

  // Derive active tab from URL
  const getActiveTab = (): Tab => {
    const path = location.pathname
    if (path.startsWith('/redirects')) return 'redirects'
    if (path.startsWith('/waf')) return 'waf'
    if (path.startsWith('/access')) return 'access'
    if (path.startsWith('/certificates')) return 'certificates'
    if (path.startsWith('/logs')) return 'logs'
    if (path.startsWith('/settings')) return 'settings'
    if (path.startsWith('/proxy-hosts') || path === '/') return 'proxy-hosts'
    if (path.startsWith('/dashboard')) return 'dashboard'
    return 'proxy-hosts'
  }

  const activeTab = getActiveTab()
  const [showForm, setShowForm] = useState(false)
  const [editingHost, setEditingHost] = useState<ProxyHost | null>(null)
  const [initialFormTab, setInitialFormTab] = useState<'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection'>('basic')
  const [showAccountSettings, setShowAccountSettings] = useState(false)
  const [isSyncing, setIsSyncing] = useState(false)

  const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth, refetchInterval: 10000 })

  const handleSyncAll = async () => {
    if (isSyncing) return

    const confirmed = confirm(t('common:actions.syncAllConfirm', 'Regenerate all Nginx configs for Proxy Hosts and Redirect Hosts?'))
    if (!confirmed) return

    setIsSyncing(true)
    try {
      await apiPost('/api/v1/proxy-hosts/sync')
      await apiPost('/api/v1/redirect-hosts/sync')
    } catch (error) {
      console.error('Sync failed:', error)
    } finally {
      setIsSyncing(false)
    }
  }

  const handleEdit = (host: ProxyHost, tab?: 'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection') => {
    setEditingHost(host)
    setInitialFormTab(tab || 'basic')
    setShowForm(true)
  }

  const handleAdd = () => {
    setEditingHost(null)
    setInitialFormTab('basic')
    setShowForm(true)
  }

  const handleCloseForm = () => {
    setShowForm(false)
    setEditingHost(null)
    setInitialFormTab('basic')
  }

  const handleTabClick = (tab: Tab) => {
    switch (tab) {
      case 'dashboard':
        navigate('/dashboard')
        break
      case 'proxy-hosts':
        navigate('/proxy-hosts')
        break
      case 'redirects':
        navigate('/redirects')
        break
      case 'waf':
        navigate('/waf/settings')
        break
      case 'access':
        navigate('/access/lists')
        break
      case 'certificates':
        navigate('/certificates')
        break
      case 'logs':
        navigate('/logs/access')
        break
      case 'settings':
        navigate('/settings/global')
        break
    }
  }

  const handleLogout = async () => {
    await logout()
    onLogout()
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex flex-col transition-colors">
      {/* Header */}
      <header className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <div className="max-w-7xl mx-auto px-4 py-3 lg:py-4 flex items-center justify-between">
          <div
            className="flex items-center gap-2 lg:gap-3 cursor-pointer hover:opacity-80 transition-opacity"
            onClick={() => navigate('/dashboard')}
          >
            <img
              src="/favicon.ico"
              alt="NPG Logo"
              className="w-8 h-8 lg:w-10 lg:h-10 rounded-lg flex-shrink-0"
            />
            <div className="hidden sm:block">
              <h1 className="text-lg lg:text-xl font-bold text-slate-900 dark:text-gray-100">{t('header.nginxProxyGuard')}</h1>
              <p className="text-xs text-slate-500 dark:text-slate-400 hidden lg:block">{t('header.subtitle')}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 lg:gap-4">
            <div className="flex items-center gap-2">
              {/* Sync All Button */}
              <button
                onClick={handleSyncAll}
                disabled={isSyncing}
                className={`p-1.5 rounded-lg transition-colors ${isSyncing
                  ? 'text-primary-500 bg-primary-50 dark:bg-primary-900/30'
                  : 'text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-700'}`}
                title={t('common:actions.syncAll', 'Sync All Configs')}
              >
                <svg className={`w-5 h-5 ${isSyncing ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
              {/* Dark Mode Toggle */}
              <button
                onClick={toggle}
                className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-700 transition-colors"
                title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
              >
                {isDark ? (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                  </svg>
                )}
              </button>
            </div>

            <span className="text-xs text-slate-400">v{health.data?.version || '...'}</span>
            {/* User Menu */}
            <div className="flex items-center gap-2 lg:gap-3 pl-2 lg:pl-4 border-l border-slate-200 dark:border-slate-700">
              <button
                onClick={() => setShowAccountSettings(true)}
                className="text-right hover:bg-slate-50 dark:hover:bg-slate-700 px-2 py-1 rounded transition-colors"
              >
                <div className="text-sm font-medium text-slate-700 dark:text-gray-200">{user.username}</div>
                <div className="text-xs text-slate-400 hidden sm:block">{user.role}</div>
              </button>
              <button
                onClick={handleLogout}
                className="text-xs lg:text-sm px-2 lg:px-3 py-1 lg:py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300 transition-colors"
              >
                {t('account.logout')}
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
        <div className="max-w-7xl mx-auto px-4 overflow-x-auto scrollbar-hide">
          <div className="flex gap-1 sm:gap-2 lg:gap-4 min-w-max">
            <button
              onClick={() => handleTabClick('dashboard')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'dashboard'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              {t('menu.dashboard')}
            </button>
            <button
              onClick={() => handleTabClick('proxy-hosts')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'proxy-hosts'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              <span className="hidden sm:inline">{t('menu.proxyHosts')}</span>
              <span className="sm:hidden">{t('menu.hosts')}</span>
            </button>
            <button
              onClick={() => handleTabClick('redirects')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'redirects'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              {t('menu.redirects')}
            </button>
            <button
              onClick={() => handleTabClick('waf')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'waf'
                ? 'border-orange-600 text-orange-600 dark:text-orange-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              <span className="hidden sm:inline">{t('menu.wafBanIp')}</span>
              <span className="sm:hidden">{t('menu.waf')}</span>
            </button>
            <button
              onClick={() => handleTabClick('access')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'access'
                ? 'border-purple-600 text-purple-600 dark:text-purple-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              <span className="hidden lg:inline">{t('menu.accessControl')}</span>
              <span className="lg:hidden">{t('menu.access')}</span>
            </button>
            <button
              onClick={() => handleTabClick('certificates')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'certificates'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              <span className="hidden sm:inline">{t('menu.certificates')}</span>
              <span className="sm:hidden">{t('menu.sslCerts')}</span>
            </button>
            <button
              onClick={() => handleTabClick('logs')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'logs'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              {t('menu.logs')}
            </button>
            <button
              onClick={() => handleTabClick('settings')}
              className={`py-3 px-2 lg:px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${activeTab === 'settings'
                ? 'border-teal-600 text-teal-600 dark:text-teal-400'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
            >
              {t('menu.settings')}
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto px-4 py-8 w-full">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/proxy-hosts" element={<ProxyHostList onEdit={handleEdit} onAdd={handleAdd} />} />
          <Route path="/certificates" element={<Navigate to="/certificates/list" replace />} />
          <Route path="/certificates/list" element={<CertificatesPage subTab="certificates" />} />
          <Route path="/certificates/history" element={<CertificatesPage subTab="history" />} />
          <Route path="/certificates/dns-providers" element={<CertificatesPage subTab="dns-providers" />} />
          <Route path="/redirects" element={<RedirectHostManager />} />
          <Route path="/waf" element={<Navigate to="/waf/settings" replace />} />
          <Route path="/waf/settings" element={<WAFPage subTab="settings" />} />
          <Route path="/waf/banned-ips" element={<WAFPage subTab="banned-ips" />} />
          <Route path="/waf/uri-blocks" element={<WAFPage subTab="uri-blocks" />} />
          <Route path="/waf/tester" element={<WAFPage subTab="tester" />} />
          <Route path="/waf/exploit-rules" element={<WAFPage subTab="exploit-rules" />} />
          <Route path="/waf/fail2ban" element={<WAFPage subTab="fail2ban" />} />
          <Route path="/access" element={<Navigate to="/access/lists" replace />} />
          <Route path="/access/lists" element={<AccessListManager />} />
          <Route path="/logs" element={<Navigate to="/logs/access" replace />} />
          <Route path="/logs/access" element={<LogsPage subTab="access" />} />
          <Route path="/logs/waf-events" element={<LogsPage subTab="waf-events" />} />
          <Route path="/logs/bot-filter" element={<LogsPage subTab="bot-filter" />} />
          <Route path="/logs/exploit-blocks" element={<LogsPage subTab="exploit-blocks" />} />
          <Route path="/logs/system" element={<LogsPage subTab="system" />} />
          <Route path="/logs/audit" element={<LogsPage subTab="audit" />} />
          <Route path="/logs/raw-files" element={<LogsPage subTab="raw-files" />} />
          <Route path="/settings" element={<Navigate to="/settings/global" replace />} />
          <Route path="/settings/global" element={<SettingsPage subTab="global" />} />
          <Route path="/settings/captcha" element={<SettingsPage subTab="captcha" />} />
          <Route path="/settings/geoip" element={<SettingsPage subTab="geoip" />} />
          <Route path="/settings/ssl" element={<SettingsPage subTab="ssl" />} />
          <Route path="/settings/maintenance" element={<SettingsPage subTab="maintenance" />} />
          <Route path="/settings/backups" element={<SettingsPage subTab="backups" />} />
          <Route path="/settings/botfilter" element={<SettingsPage subTab="botfilter" />} />
          <Route path="/settings/waf-auto-ban" element={<SettingsPage subTab="waf-auto-ban" />} />
          <Route path="/settings/system-logs" element={<SettingsPage subTab="system-logs" />} />
        </Routes>
      </main>

      {/* Form Modal */}
      {showForm && (
        <ProxyHostForm
          host={editingHost}
          initialTab={initialFormTab}
          onClose={handleCloseForm}
        />
      )}

      {/* Account Settings Modal */}
      {showAccountSettings && (
        <AccountSettings
          onClose={() => setShowAccountSettings(false)}
          onLogout={handleLogout}
        />
      )}

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-2 text-sm text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-2">
              <img src="/favicon.ico" alt="NPG Logo" className="w-5 h-5 rounded" />
              <span className="font-semibold text-slate-700 dark:text-gray-300">Nginx Proxy Guard</span>
              <span className="text-slate-400">v{health.data?.version || '0.0.0'}</span>
            </div>
            <div className="flex items-center gap-4">
              <a
                href="https://github.com/svrforum/NginxProxyGuard"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-slate-700 dark:hover:text-slate-200 transition-colors flex items-center gap-1"
              >
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                  <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
                </svg>
                {t('footer.github')}
              </a>
              <span className="text-slate-300 dark:text-slate-600">|</span>
              <a
                href="https://nginxproxyguard.com/en/docs/introduction"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
              >
                {t('footer.documentation')}
              </a>
            </div>
            <div className="text-slate-400 text-xs">
              © {new Date().getFullYear()} Nginx Proxy Guard. {t('footer.allRightsReserved')}
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

// Certificates Page Component
function CertificatesPage({ subTab }: { subTab: 'certificates' | 'history' | 'dns-providers' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for certificates */}
      <div className="border-b border-slate-200">
        <div className="flex gap-4">
          <button
            onClick={() => navigate('/certificates/list')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'certificates'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.certificates.list')}
          </button>
          <button
            onClick={() => navigate('/certificates/history')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'history'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.certificates.history')}
          </button>
          <button
            onClick={() => navigate('/certificates/dns-providers')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'dns-providers'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.certificates.dnsProviders')}
          </button>
        </div>
      </div>

      {subTab === 'certificates' && <CertificateList />}
      {subTab === 'history' && <CertificateHistoryList />}
      {subTab === 'dns-providers' && <DNSProviderList />}
    </div>
  )
}

// WAF Page Component
function WAFPage({ subTab }: { subTab: 'settings' | 'tester' | 'banned-ips' | 'uri-blocks' | 'exploit-rules' | 'fail2ban' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for WAF */}
      <div className="border-b border-slate-200">
        <div className="flex gap-4">
          <button
            onClick={() => navigate('/waf/settings')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'settings'
              ? 'border-orange-600 text-orange-600 dark:text-orange-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.ruleSettings')}
          </button>
          <button
            onClick={() => navigate('/waf/banned-ips')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'banned-ips'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.bannedIps')}
          </button>
          <button
            onClick={() => navigate('/waf/uri-blocks')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'uri-blocks'
              ? 'border-rose-600 text-rose-600 dark:text-rose-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.uriBlocks')}
          </button>
          <button
            onClick={() => navigate('/waf/exploit-rules')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'exploit-rules'
              ? 'border-amber-600 text-amber-600 dark:text-amber-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.exploitRules')}
          </button>
          <button
            onClick={() => navigate('/waf/fail2ban')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'fail2ban'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.fail2ban')}
          </button>
          <button
            onClick={() => navigate('/waf/tester')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'tester'
              ? 'border-purple-600 text-purple-600 dark:text-purple-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.tester')}
          </button>
        </div>
      </div>

      {subTab === 'settings' && <WAFSettings />}
      {subTab === 'banned-ips' && <BannedIPList />}
      {subTab === 'uri-blocks' && <URIBlockManager />}
      {subTab === 'exploit-rules' && <ExploitBlockRules />}
      {subTab === 'fail2ban' && <Fail2banManagement />}
      {subTab === 'tester' && <WAFTester />}
    </div>
  )
}

// Logs Page Component
function LogsPage({ subTab }: { subTab: 'access' | 'waf-events' | 'bot-filter' | 'exploit-blocks' | 'system' | 'audit' | 'raw-files' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for logs */}
      <div className="border-b border-slate-200 overflow-x-auto scrollbar-hide">
        <div className="flex gap-2 lg:gap-4 min-w-max">
          <button
            onClick={() => navigate('/logs/access')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'access'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.access')}
          </button>
          <button
            onClick={() => navigate('/logs/waf-events')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'waf-events'
              ? 'border-orange-600 text-orange-600 dark:text-orange-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.wafEvents')}
          </button>
          <button
            onClick={() => navigate('/logs/bot-filter')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'bot-filter'
              ? 'border-purple-600 text-purple-600 dark:text-purple-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.botFilter')}
          </button>
          <button
            onClick={() => navigate('/logs/exploit-blocks')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'exploit-blocks'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.exploitBlocks')}
          </button>
          <button
            onClick={() => navigate('/logs/system')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'system'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.system')}
          </button>
          <button
            onClick={() => navigate('/logs/audit')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'audit'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.audit')}
          </button>
          <button
            onClick={() => navigate('/logs/raw-files')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'raw-files'
              ? 'border-amber-600 text-amber-600 dark:text-amber-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.rawFiles')}
          </button>
        </div>
      </div>

      {subTab === 'system' ? (
        <SystemLogViewer />
      ) : subTab === 'audit' ? (
        <AuditLog />
      ) : subTab === 'raw-files' ? (
        <RawLogFiles />
      ) : subTab === 'bot-filter' ? (
        <BotFilterLogs />
      ) : subTab === 'exploit-blocks' ? (
        <ExploitBlockLogs />
      ) : (
        <LogViewer logType={subTab === 'waf-events' ? 'modsec' : subTab} />
      )}
    </div>
  )
}

// Settings Page Component
function SettingsPage({ subTab }: { subTab: 'global' | 'captcha' | 'geoip' | 'ssl' | 'maintenance' | 'backups' | 'botfilter' | 'waf-auto-ban' | 'system-logs' }) {
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
    </div>
  )
}

type AuthState = 'loading' | 'unauthenticated' | 'authenticated' | 'initial-setup'

function App() {
  const [authState, setAuthState] = useState<AuthState>('loading')
  const [user, setUser] = useState<User | null>(null)

  // Load saved font family on initial render
  useEffect(() => {
    const savedFont = localStorage.getItem('npg_font_family')
    if (savedFont) {
      document.documentElement.setAttribute('data-font', savedFont)
    }
  }, [])

  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    try {
      const token = getToken()
      if (!token) {
        setAuthState('unauthenticated')
        return
      }

      const status = await getAuthStatus()
      if (status.authenticated && status.user) {
        setUser(status.user)
        if (status.user.is_initial_setup) {
          setAuthState('initial-setup')
        } else {
          setAuthState('authenticated')
        }
      } else {
        setAuthState('unauthenticated')
      }
    } catch {
      setAuthState('unauthenticated')
    }
  }

  const handleLogin = async () => {
    await checkAuth()
  }

  const handleLogout = () => {
    setUser(null)
    setAuthState('unauthenticated')
  }

  const handleSetupComplete = () => {
    setUser(null)
    setAuthState('unauthenticated')
  }

  // Loading state
  if (authState === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900">
        <div className="text-center">
          <svg className="animate-spin w-12 h-12 text-primary-500 mx-auto" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
        </div>
      </div>
    )
  }

  // Login required
  if (authState === 'unauthenticated') {
    return <Login onLogin={handleLogin} />
  }

  // Initial setup required
  if (authState === 'initial-setup' && user) {
    return <InitialSetup user={user} onComplete={handleSetupComplete} />
  }

  // Authenticated
  if (authState === 'authenticated' && user) {
    return (
      <ErrorBoundary>
        <BrowserRouter>
          <AppContent user={user} onLogout={handleLogout} />
        </BrowserRouter>
      </ErrorBoundary>
    )
  }

  return null
}

export default App

import React, { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { ProxyHost } from '../types/proxy-host'
import RateLimitSettings from './proxy-host-settings/RateLimitSettings'
import Fail2banSettings from './proxy-host-settings/Fail2banSettings'
import BotFilterSettings from './proxy-host-settings/BotFilterSettings'
import SecurityHeadersSettings from './proxy-host-settings/SecurityHeadersSettings'
import BannedIPsSettings from './proxy-host-settings/BannedIPsSettings'

interface ProxyHostSettingsProps {
  host: ProxyHost
  onClose: () => void
}

type TabType = 'rate-limit' | 'fail2ban' | 'bot-filter' | 'security-headers' | 'banned-ips'

export function ProxyHostSettings({ host, onClose }: ProxyHostSettingsProps) {
  const [activeTab, setActiveTab] = useState<TabType>('rate-limit')
  const queryClient = useQueryClient()

  const tabs: { id: TabType; label: string; icon: React.JSX.Element }[] = [
    {
      id: 'rate-limit',
      label: 'Rate Limit',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      id: 'fail2ban',
      label: 'Fail2ban',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
    },
    {
      id: 'security-headers',
      label: 'Security Headers',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      id: 'banned-ips',
      label: 'Banned IPs',
      icon: (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
    },
  ]

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Advanced Settings</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">{host.domain_names.join(', ')}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-400 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="px-6 pt-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 border-b-2 border-primary-600'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-700'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
          {activeTab === 'rate-limit' && (
            <RateLimitSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'fail2ban' && (
            <Fail2banSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'bot-filter' && (
            <BotFilterSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'security-headers' && (
            <SecurityHeadersSettings hostId={host.id} queryClient={queryClient} />
          )}
          {activeTab === 'banned-ips' && (
            <BannedIPsSettings hostId={host.id} queryClient={queryClient} />
          )}
        </div>
      </div>
    </div>
  )
}

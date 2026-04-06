import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  listAllURIBlocks,
  updateURIBlock,
  deleteURIBlock,
  type URIBlockWithHost,
  getGlobalURIBlock,
  updateGlobalURIBlock,
  type GlobalURIBlock
} from '../api/security'
import { fetchProxyHosts } from '../api/proxy-hosts'
import { api } from '../api/client'
import type { URIBlockRule, URIMatchType } from '../types/security'
import type { ProxyHost } from '../types/proxy-host'
import { HostDetailModal } from './uri-block/HostDetailModal'
import { GlobalTab } from './uri-block/GlobalTab'
import { RulesTab } from './uri-block/RulesTab'
import { HistoryTab, type URIBlockHistoryEntry } from './uri-block/HistoryTab'

export function URIBlockManager() {
  const { t } = useTranslation('waf')
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'global' | 'rules' | 'history'>('global')
  const [hostFilter, setHostFilter] = useState<string>('all')

  // Host detail modal state
  const [editingBlock, setEditingBlock] = useState<URIBlockWithHost | null>(null)

  // New host modal
  const [showNewHostModal, setShowNewHostModal] = useState(false)
  const [selectedNewHostId, setSelectedNewHostId] = useState('')

  // Global URI block state
  const [globalPattern, setGlobalPattern] = useState('')
  const [globalMatchType, setGlobalMatchType] = useState<URIMatchType>('prefix')
  const [globalDescription, setGlobalDescription] = useState('')
  const [globalExceptionIP, setGlobalExceptionIP] = useState('')
  const [showGlobalAddForm, setShowGlobalAddForm] = useState(false)

  // Pending changes state for global block
  const [pendingGlobalEnabled, setPendingGlobalEnabled] = useState<boolean | null>(null)
  const [pendingGlobalAllowPrivate, setPendingGlobalAllowPrivate] = useState<boolean | null>(null)
  const [pendingGlobalExceptionIPs, setPendingGlobalExceptionIPs] = useState<string[] | null>(null)
  const [pendingGlobalRules, setPendingGlobalRules] = useState<GlobalURIBlock['rules'] | null>(null)
  const [globalSaveMessage, setGlobalSaveMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Global URI block query
  const { data: globalBlock, isLoading: globalLoading } = useQuery({
    queryKey: ['global-uri-block'],
    queryFn: getGlobalURIBlock,
    refetchInterval: 60000,
  })

  const { data: blocks = [], isLoading, error } = useQuery({
    queryKey: ['uri-blocks'],
    queryFn: listAllURIBlocks,
    refetchInterval: 60000,
  })

  // Fetch all proxy hosts for new host selection
  const { data: proxyHostsData } = useQuery({
    queryKey: ['proxy-hosts-all'],
    queryFn: () => fetchProxyHosts(1, 1000),
  })

  // Fetch URI block history from audit logs
  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ['uri-block-history'],
    queryFn: async () => {
      const response = await api.get<{ logs: URIBlockHistoryEntry[]; total: number }>(
        '/api/v1/audit-logs?resource_type=uri_block&limit=100'
      )
      return response.logs || []
    },
    enabled: activeTab === 'history',
    refetchInterval: 60000,
  })

  // Update editing state when block data changes
  useEffect(() => {
    if (editingBlock) {
      const updated = blocks.find(b => b.proxy_host_id === editingBlock.proxy_host_id)
      if (updated) {
        setEditingBlock(updated)
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [blocks])

  // Reset pending state when globalBlock data loads
  useEffect(() => {
    if (globalBlock) {
      setPendingGlobalEnabled(null)
      setPendingGlobalAllowPrivate(null)
      setPendingGlobalExceptionIPs(null)
      setPendingGlobalRules(null)
    }
  }, [globalBlock])

  // Computed values for global block (show pending if exists, otherwise original)
  const effectiveGlobalEnabled = pendingGlobalEnabled !== null ? pendingGlobalEnabled : (globalBlock?.enabled ?? false)
  const effectiveGlobalAllowPrivate = pendingGlobalAllowPrivate !== null ? pendingGlobalAllowPrivate : (globalBlock?.allow_private_ips ?? true)
  const effectiveGlobalExceptionIPs = pendingGlobalExceptionIPs !== null ? pendingGlobalExceptionIPs : (globalBlock?.exception_ips ?? [])
  const effectiveGlobalRules = pendingGlobalRules !== null ? pendingGlobalRules : (globalBlock?.rules ?? [])

  // Check if there are pending changes
  const hasGlobalPendingChanges = pendingGlobalEnabled !== null ||
    pendingGlobalAllowPrivate !== null ||
    pendingGlobalExceptionIPs !== null ||
    pendingGlobalRules !== null

  // Get unique hosts for filter
  const hosts = [...new Set(blocks.map(b => b.domain_names[0]))].sort()

  // Filter blocks
  const filteredBlocks = hostFilter === 'all'
    ? blocks
    : blocks.filter(b => b.domain_names[0] === hostFilter)

  // Count total rules
  const totalRules = blocks.reduce((acc, b) => acc + b.rules.filter(r => r.enabled).length, 0)
  const totalHosts = blocks.length

  // Get hosts without URI blocks
  const proxyHosts = proxyHostsData?.data || []
  const hostsWithBlocks = new Set(blocks.map(b => b.proxy_host_id))
  const hostsWithoutBlocks = proxyHosts.filter((h: ProxyHost) => !hostsWithBlocks.has(h.id))

  const updateMutation = useMutation({
    mutationFn: async ({ proxyHostId, data }: { proxyHostId: string; data: { enabled: boolean; rules: URIBlockRule[]; exception_ips: string[]; allow_private_ips: boolean } }) => {
      return updateURIBlock(proxyHostId, data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
    },
  })

  // Global URI block mutations
  const updateGlobalMutation = useMutation({
    mutationFn: async (data: Partial<GlobalURIBlock>) => {
      return updateGlobalURIBlock(data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-uri-block'] })
      queryClient.invalidateQueries({ queryKey: ['uri-block-history'] })
    },
  })

  // Delete URI block mutation
  const deleteURIBlockMutation = useMutation({
    mutationFn: async (proxyHostId: string) => {
      return deleteURIBlock(proxyHostId)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
      queryClient.invalidateQueries({ queryKey: ['uri-block-history'] })
      closeHostModal()
    },
    onError: (error) => {
      console.error('Failed to delete URI block:', error)
      alert(t('common:error') + ': ' + (error instanceof Error ? error.message : 'Unknown error'))
    },
  })

  const openHostModal = (block: URIBlockWithHost) => {
    setEditingBlock(block)
  }

  const closeHostModal = () => {
    setEditingBlock(null)
  }

  const handleToggleEnabled = (block: URIBlockWithHost) => {
    updateMutation.mutate({
      proxyHostId: block.proxy_host_id,
      data: {
        enabled: !block.enabled,
        rules: block.rules,
        exception_ips: block.exception_ips,
        allow_private_ips: block.allow_private_ips,
      },
    })
  }

  const handleCreateNewHost = () => {
    if (!selectedNewHostId) return
    updateMutation.mutate({
      proxyHostId: selectedNewHostId,
      data: {
        enabled: true,
        rules: [],
        exception_ips: [],
        allow_private_ips: true,
      },
    }, {
      onSuccess: () => {
        setShowNewHostModal(false)
        setSelectedNewHostId('')
        setTimeout(() => {
          const newBlock = blocks.find(b => b.proxy_host_id === selectedNewHostId)
          if (newBlock) openHostModal(newBlock)
        }, 500)
      }
    })
  }

  // Save global changes
  const handleSaveGlobalChanges = async () => {
    try {
      await updateGlobalMutation.mutateAsync({
        enabled: effectiveGlobalEnabled,
        rules: effectiveGlobalRules,
        exception_ips: effectiveGlobalExceptionIPs,
        allow_private_ips: effectiveGlobalAllowPrivate,
      })
      setPendingGlobalEnabled(null)
      setPendingGlobalAllowPrivate(null)
      setPendingGlobalExceptionIPs(null)
      setPendingGlobalRules(null)
      const hostCount = proxyHosts.length
      setGlobalSaveMessage({
        type: 'success',
        message: t('uriBlock.global.saveSuccess', { count: hostCount }) || `Settings saved and applied to ${hostCount} hosts`,
      })
      setTimeout(() => setGlobalSaveMessage(null), 5000)
    } catch {
      setGlobalSaveMessage({
        type: 'error',
        message: t('uriBlock.global.saveFailed') || 'Failed to save settings',
      })
      setTimeout(() => setGlobalSaveMessage(null), 5000)
    }
  }

  // Discard global changes
  const handleDiscardGlobalChanges = () => {
    setPendingGlobalEnabled(null)
    setPendingGlobalAllowPrivate(null)
    setPendingGlobalExceptionIPs(null)
    setPendingGlobalRules(null)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 p-4 rounded-lg">
        {t('common:error')}: {(error as Error).message}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
            {t('uriBlock.title')}
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {t('uriBlock.subtitle')}
          </p>
        </div>
        <button
          onClick={() => setShowNewHostModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-lg font-medium transition-colors"
          disabled={hostsWithoutBlocks.length === 0}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          {t('uriBlock.addHost')}
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white dark:bg-slate-800 rounded-lg p-4 border border-slate-200 dark:border-slate-700">
          <div className="text-2xl font-bold text-slate-900 dark:text-white">{totalHosts}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">{t('uriBlock.stats.totalHosts')}</div>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg p-4 border border-slate-200 dark:border-slate-700">
          <div className="text-2xl font-bold text-rose-600 dark:text-rose-400">{totalRules}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">{t('uriBlock.stats.totalRules')}</div>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg p-4 border border-slate-200 dark:border-slate-700">
          <div className="text-2xl font-bold text-green-600 dark:text-green-400">{blocks.filter(b => b.enabled && b.host_enabled).length}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">{t('uriBlock.stats.activeHosts')}</div>
        </div>
        <div className="bg-white dark:bg-slate-800 rounded-lg p-4 border border-slate-200 dark:border-slate-700">
          <div className="text-2xl font-bold text-slate-400 dark:text-slate-500">{blocks.filter(b => !b.enabled || !b.host_enabled).length}</div>
          <div className="text-sm text-slate-500 dark:text-slate-400">{t('uriBlock.stats.disabledHosts')}</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-700">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('global')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'global'
                ? 'border-rose-500 text-rose-600 dark:text-rose-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300'
            }`}
          >
            {t('uriBlock.tabs.global', 'Global Rules')}
          </button>
          <button
            onClick={() => setActiveTab('rules')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'rules'
                ? 'border-rose-500 text-rose-600 dark:text-rose-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300'
            }`}
          >
            {t('uriBlock.tabs.rules')}
          </button>
          <button
            onClick={() => setActiveTab('history')}
            className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'history'
                ? 'border-rose-500 text-rose-600 dark:text-rose-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300'
            }`}
          >
            {t('uriBlock.tabs.history')}
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'global' && (
        <GlobalTab
          globalLoading={globalLoading}
          globalSaveMessage={globalSaveMessage}
          hasGlobalPendingChanges={hasGlobalPendingChanges}
          effectiveGlobalEnabled={effectiveGlobalEnabled}
          effectiveGlobalAllowPrivate={effectiveGlobalAllowPrivate}
          effectiveGlobalExceptionIPs={effectiveGlobalExceptionIPs}
          effectiveGlobalRules={effectiveGlobalRules}
          updateGlobalIsPending={updateGlobalMutation.isPending}
          showGlobalAddForm={showGlobalAddForm}
          setShowGlobalAddForm={setShowGlobalAddForm}
          globalPattern={globalPattern}
          setGlobalPattern={setGlobalPattern}
          globalMatchType={globalMatchType}
          setGlobalMatchType={setGlobalMatchType}
          globalDescription={globalDescription}
          setGlobalDescription={setGlobalDescription}
          globalExceptionIP={globalExceptionIP}
          setGlobalExceptionIP={setGlobalExceptionIP}
          setPendingGlobalEnabled={setPendingGlobalEnabled}
          setPendingGlobalAllowPrivate={setPendingGlobalAllowPrivate}
          setPendingGlobalExceptionIPs={setPendingGlobalExceptionIPs}
          setPendingGlobalRules={setPendingGlobalRules}
          handleSaveGlobalChanges={handleSaveGlobalChanges}
          handleDiscardGlobalChanges={handleDiscardGlobalChanges}
        />
      )}

      {activeTab === 'rules' && (
        <RulesTab
          hostFilter={hostFilter}
          setHostFilter={setHostFilter}
          hosts={hosts}
          filteredBlocks={filteredBlocks}
          updateIsPending={updateMutation.isPending}
          deleteIsPending={deleteURIBlockMutation.isPending}
          onToggleEnabled={handleToggleEnabled}
          onOpenHostModal={openHostModal}
          onDeleteBlock={(proxyHostId) => deleteURIBlockMutation.mutate(proxyHostId)}
        />
      )}

      {activeTab === 'history' && (
        <HistoryTab
          historyLoading={historyLoading}
          historyData={historyData}
        />
      )}

      {/* Host Detail Modal */}
      {editingBlock && (
        <HostDetailModal
          block={editingBlock}
          proxyHostsCount={proxyHosts.length}
          onClose={closeHostModal}
        />
      )}

      {/* New Host Modal */}
      {showNewHostModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                {t('uriBlock.newHostModal.title')}
              </h2>
            </div>
            <div className="p-6">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                {t('uriBlock.newHostModal.selectHost')}
              </label>
              {hostsWithoutBlocks.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400 italic">
                  {t('uriBlock.newHostModal.noAvailableHosts')}
                </p>
              ) : (
                <select
                  value={selectedNewHostId}
                  onChange={(e) => setSelectedNewHostId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                >
                  <option value="">{t('uriBlock.modal.selectHostPlaceholder')}</option>
                  {hostsWithoutBlocks.map((host: ProxyHost) => (
                    <option key={host.id} value={host.id}>
                      {host.domain_names[0]} {host.domain_names.length > 1 ? `(+${host.domain_names.length - 1})` : ''}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 flex justify-end gap-3">
              <button
                onClick={() => { setShowNewHostModal(false); setSelectedNewHostId(''); }}
                className="px-4 py-2 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                {t('common:cancel')}
              </button>
              <button
                onClick={handleCreateNewHost}
                disabled={!selectedNewHostId || updateMutation.isPending}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors"
              >
                {updateMutation.isPending ? t('common:processing') : t('uriBlock.newHostModal.create')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  listAllURIBlocks, 
  updateURIBlock, 
  removeURIBlockRule, 
  addURIBlockRule, 
  bulkAddURIBlockRule, 
  deleteURIBlock,
  type URIBlockWithHost, 
  getGlobalURIBlock, 
  updateGlobalURIBlock, 
  type GlobalURIBlock 
} from '../api/security'
import { fetchProxyHosts } from '../api/proxy-hosts'
import { api } from '../api/client'
import type { URIBlockRule, URIMatchType, AddURIBlockRuleRequest } from '../types/security'
import type { ProxyHost } from '../types/proxy-host'

interface URIBlockHistoryEntry {
  id: string
  action: string
  resource_type: string
  resource_id: string
  user_email: string
  ip_address: string
  details: {
    host?: string
    name?: string
    enabled?: boolean
    action?: string
    pattern?: string
    match_type?: string
    rule_id?: string
  }
  created_at: string
}

function formatDate(dateStr: string, locale?: string): string {
  return new Date(dateStr).toLocaleString(locale || 'ko-KR')
}

function getMatchTypeLabel(matchType: URIMatchType, t: (key: string) => string): string {
  switch (matchType) {
    case 'exact': return t('uriBlock.matchTypes.exact')
    case 'prefix': return t('uriBlock.matchTypes.prefix')
    case 'regex': return t('uriBlock.matchTypes.regex')
    default: return matchType
  }
}

function getMatchTypeColor(matchType: URIMatchType): string {
  switch (matchType) {
    case 'exact': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
    case 'prefix': return 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400'
    case 'regex': return 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400'
    default: return 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300'
  }
}

export function URIBlockManager() {
  const { t, i18n } = useTranslation('waf')
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'global' | 'rules' | 'history'>('global')
  const [hostFilter, setHostFilter] = useState<string>('all')

  // Host detail modal state
  const [editingBlock, setEditingBlock] = useState<URIBlockWithHost | null>(null)
  const [showAddRuleForm, setShowAddRuleForm] = useState(false)
  const [newPattern, setNewPattern] = useState('')
  const [newMatchType, setNewMatchType] = useState<URIMatchType>('prefix')
  const [newDescription, setNewDescription] = useState('')
  const [applyToAllHosts, setApplyToAllHosts] = useState(false)

  // Settings state for editing
  const [editAllowPrivateIPs, setEditAllowPrivateIPs] = useState(true)
  const [newExceptionIP, setNewExceptionIP] = useState('')

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
    refetchInterval: 30000,
  })

  const { data: blocks = [], isLoading, error } = useQuery({
    queryKey: ['uri-blocks'],
    queryFn: listAllURIBlocks,
    refetchInterval: 30000,
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
    refetchInterval: 30000,
  })

  // Update editing state when block data changes
  useEffect(() => {
    if (editingBlock) {
      const updated = blocks.find(b => b.proxy_host_id === editingBlock.proxy_host_id)
      if (updated) {
        setEditingBlock(updated)
        setEditAllowPrivateIPs(updated.allow_private_ips)
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

  // Save global changes
  const handleSaveGlobalChanges = async () => {
    try {
      await updateGlobalMutation.mutateAsync({
        enabled: effectiveGlobalEnabled,
        rules: effectiveGlobalRules,
        exception_ips: effectiveGlobalExceptionIPs,
        allow_private_ips: effectiveGlobalAllowPrivate,
      })
      // Reset pending state
      setPendingGlobalEnabled(null)
      setPendingGlobalAllowPrivate(null)
      setPendingGlobalExceptionIPs(null)
      setPendingGlobalRules(null)
      // Show success message with host count
      const hostCount = proxyHosts.length
      setGlobalSaveMessage({
        type: 'success',
        message: t('uriBlock.global.saveSuccess', { count: hostCount }) || `Settings saved and applied to ${hostCount} hosts`,
      })
      // Clear message after 5 seconds
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

  const removeRuleMutation = useMutation({
    mutationFn: async ({ proxyHostId, ruleId }: { proxyHostId: string; ruleId: string }) => {
      return removeURIBlockRule(proxyHostId, ruleId)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
    },
  })

  const addRuleMutation = useMutation({
    mutationFn: async ({ proxyHostId, rule }: { proxyHostId: string; rule: AddURIBlockRuleRequest }) => {
      return addURIBlockRule(proxyHostId, rule)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
      resetAddRuleForm()
    },
  })

  const bulkAddRuleMutation = useMutation({
    mutationFn: async (rule: { pattern: string; match_type: URIMatchType; description?: string }) => {
      return bulkAddURIBlockRule({
        pattern: rule.pattern,
        match_type: rule.match_type,
        description: rule.description,
      })
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
      queryClient.invalidateQueries({ queryKey: ['uri-block-history'] })
      resetAddRuleForm()
      alert(t('uriBlock.bulkAdd.success', { count: data.added_count, total: data.total_hosts }))
    },
    onError: (error) => {
      alert(t('uriBlock.bulkAdd.failed', { error: (error as Error).message }))
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
  })

  const openHostModal = (block: URIBlockWithHost) => {
    setEditingBlock(block)
    setEditAllowPrivateIPs(block.allow_private_ips)
    setShowAddRuleForm(false)
    resetAddRuleForm()
  }

  const closeHostModal = () => {
    setEditingBlock(null)
    setShowAddRuleForm(false)
    resetAddRuleForm()
  }

  const resetAddRuleForm = () => {
    setNewPattern('')
    setNewMatchType('prefix')
    setNewDescription('')
    setApplyToAllHosts(false)
  }

  const handleAddRule = () => {
    if (!newPattern.trim()) return

    if (applyToAllHosts) {
      // Bulk add to all hosts
      bulkAddRuleMutation.mutate({
        pattern: newPattern.trim(),
        match_type: newMatchType,
        description: newDescription.trim() || undefined,
      })
    } else {
      // Add to current host only
      if (!editingBlock) return
      addRuleMutation.mutate({
        proxyHostId: editingBlock.proxy_host_id,
        rule: {
          pattern: newPattern.trim(),
          match_type: newMatchType,
          description: newDescription.trim() || undefined,
          enabled: true,
        },
      })
    }
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

  const handleAddExceptionIP = () => {
    if (!editingBlock || !newExceptionIP.trim()) return
    const newIPs = [...editingBlock.exception_ips, newExceptionIP.trim()]
    updateMutation.mutate({
      proxyHostId: editingBlock.proxy_host_id,
      data: {
        enabled: editingBlock.enabled,
        rules: editingBlock.rules,
        exception_ips: newIPs,
        allow_private_ips: editingBlock.allow_private_ips,
      },
    })
    setNewExceptionIP('')
  }

  const handleRemoveExceptionIP = (ip: string) => {
    if (!editingBlock) return
    const newIPs = editingBlock.exception_ips.filter(i => i !== ip)
    updateMutation.mutate({
      proxyHostId: editingBlock.proxy_host_id,
      data: {
        enabled: editingBlock.enabled,
        rules: editingBlock.rules,
        exception_ips: newIPs,
        allow_private_ips: editingBlock.allow_private_ips,
      },
    })
  }

  const handleCreateNewHost = () => {
    if (!selectedNewHostId) return
    // Create empty URI block for new host
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
        // Open the newly created block for editing
        setTimeout(() => {
          const newBlock = blocks.find(b => b.proxy_host_id === selectedNewHostId)
          if (newBlock) openHostModal(newBlock)
        }, 500)
      }
    })
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

      {/* Global Tab Content */}
      {activeTab === 'global' && (
        <div className="space-y-6">
          {globalLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-rose-600"></div>
            </div>
          ) : (
            <>
              {/* Save Message */}
              {globalSaveMessage && (
                <div className={`mb-4 p-4 rounded-lg flex items-center gap-3 ${
                  globalSaveMessage.type === 'success'
                    ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-800 dark:text-green-300'
                    : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-800 dark:text-red-300'
                }`}>
                  {globalSaveMessage.type === 'success' ? (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  )}
                  <span>{globalSaveMessage.message}</span>
                </div>
              )}

              {/* Pending Changes Banner */}
              {hasGlobalPendingChanges && (
                <div className="mb-4 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-3 text-amber-800 dark:text-amber-300">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <span className="font-medium">{t('uriBlock.global.unsavedChanges', 'You have unsaved changes')}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleDiscardGlobalChanges}
                      className="px-3 py-1.5 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded transition-colors"
                    >
                      {t('common:buttons.discard', 'Discard')}
                    </button>
                    <button
                      onClick={handleSaveGlobalChanges}
                      disabled={updateGlobalMutation.isPending}
                      className="px-4 py-1.5 text-sm bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded font-medium transition-colors flex items-center gap-2"
                    >
                      {updateGlobalMutation.isPending && (
                        <svg className="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" strokeDasharray="50 20" />
                        </svg>
                      )}
                      {t('common:buttons.save', 'Save')}
                    </button>
                  </div>
                </div>
              )}

              {/* Global Enable Toggle */}
              <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-6">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                      {t('uriBlock.global.title', 'Global URI Blocking')}
                    </h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      {t('uriBlock.global.description', 'These rules apply to ALL proxy hosts automatically.')}
                    </p>
                  </div>
                  <button
                    onClick={() => setPendingGlobalEnabled(!effectiveGlobalEnabled)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                      effectiveGlobalEnabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
                    }`}
                  >
                    <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
                      effectiveGlobalEnabled ? 'translate-x-6' : 'translate-x-1'
                    }`} />
                  </button>
                </div>

                {/* Global Rules */}
                <div className="border-t border-slate-200 dark:border-slate-700 pt-4 mt-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="font-medium text-slate-900 dark:text-white">
                      {t('uriBlock.global.rules', 'Rules')} ({effectiveGlobalRules.length})
                    </h4>
                    <button
                      onClick={() => setShowGlobalAddForm(!showGlobalAddForm)}
                      className="text-sm text-rose-600 hover:text-rose-700 dark:text-rose-400 font-medium flex items-center gap-1"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                      </svg>
                      {t('uriBlock.addRule')}
                    </button>
                  </div>

                  {/* Add Rule Form */}
                  {showGlobalAddForm && (
                    <div className="mb-4 p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg space-y-3">
                      <div className="grid grid-cols-3 gap-3">
                        <div className="col-span-2">
                          <input
                            type="text"
                            value={globalPattern}
                            onChange={(e) => setGlobalPattern(e.target.value)}
                            placeholder={t('uriBlock.modal.patternPlaceholder')}
                            className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white font-mono text-sm"
                          />
                        </div>
                        <div>
                          <select
                            value={globalMatchType}
                            onChange={(e) => setGlobalMatchType(e.target.value as URIMatchType)}
                            className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                          >
                            <option value="prefix">{t('uriBlock.matchTypes.prefix')}</option>
                            <option value="exact">{t('uriBlock.matchTypes.exact')}</option>
                            <option value="regex">{t('uriBlock.matchTypes.regex')}</option>
                          </select>
                        </div>
                      </div>
                      <div className="flex gap-3">
                        <input
                          type="text"
                          value={globalDescription}
                          onChange={(e) => setGlobalDescription(e.target.value)}
                          placeholder={t('uriBlock.modal.descriptionPlaceholder')}
                          className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                        />
                        <button
                          onClick={() => {
                            if (globalPattern.trim()) {
                              // Add rule to pending state
                              const newRule = {
                                id: `temp-${Date.now()}`,
                                pattern: globalPattern.trim(),
                                match_type: globalMatchType,
                                description: globalDescription.trim() || undefined,
                                enabled: true,
                              }
                              setPendingGlobalRules([...effectiveGlobalRules, newRule])
                              // Reset form
                              setGlobalPattern('')
                              setGlobalDescription('')
                              setShowGlobalAddForm(false)
                            }
                          }}
                          disabled={!globalPattern.trim()}
                          className="px-4 py-2 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
                        >
                          {t('uriBlock.modal.addButton')}
                        </button>
                      </div>
                      {/* Quick Templates */}
                      <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-200 dark:border-slate-600">
                        <span className="text-xs text-slate-500 dark:text-slate-400">{t('uriBlock.modal.quickTemplates')}:</span>
                        {[
                          { p: '/wp-admin', t: 'prefix', d: 'Block WP Admin' },
                          { p: '/xmlrpc.php', t: 'exact', d: 'Block XML-RPC' },
                          { p: '/wp-login.php', t: 'exact', d: 'Block WP Login' },
                          { p: '\\.php$', t: 'regex', d: 'Block PHP' },
                          { p: '/.env', t: 'prefix', d: 'Block .env' },
                          { p: '/.git', t: 'prefix', d: 'Block .git' },
                        ].map(({ p, t: type, d }) => (
                          <button
                            key={p}
                            onClick={() => { setGlobalPattern(p); setGlobalMatchType(type as URIMatchType); setGlobalDescription(d); }}
                            className="px-2 py-0.5 text-xs bg-slate-200 dark:bg-slate-600 text-slate-700 dark:text-slate-300 rounded hover:bg-slate-300 dark:hover:bg-slate-500"
                          >
                            {p}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Rules List */}
                  <div className="space-y-2">
                    {effectiveGlobalRules.length === 0 ? (
                      <p className="text-sm text-slate-500 dark:text-slate-400 italic py-4 text-center">
                        {t('uriBlock.noRules')}
                      </p>
                    ) : (
                      effectiveGlobalRules.map((rule) => (
                        <div
                          key={rule.id}
                          className={`flex items-center justify-between p-3 rounded-lg border ${
                            rule.enabled
                              ? 'bg-rose-50 dark:bg-rose-900/20 border-rose-200 dark:border-rose-800'
                              : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 opacity-60'
                          }`}
                        >
                          <div className="flex items-center gap-3 flex-1 min-w-0">
                            <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getMatchTypeColor(rule.match_type)}`}>
                              {getMatchTypeLabel(rule.match_type, t)}
                            </span>
                            <code className="font-mono text-sm text-slate-900 dark:text-white truncate">
                              {rule.pattern}
                            </code>
                            {rule.description && (
                              <span className="text-sm text-slate-500 dark:text-slate-400 truncate">
                                - {rule.description}
                              </span>
                            )}
                            {rule.id.startsWith('temp-') && (
                              <span className="px-1.5 py-0.5 text-xs bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 rounded">
                                {t('common:buttons.new', 'New')}
                              </span>
                            )}
                          </div>
                          <button
                            onClick={() => {
                              if (confirm(t('uriBlock.confirmDelete'))) {
                                // Remove rule from pending state
                                setPendingGlobalRules(effectiveGlobalRules.filter(r => r.id !== rule.id))
                              }
                            }}
                            className="p-1.5 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/30 rounded shrink-0"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Global Exception IPs */}
                <div className="border-t border-slate-200 dark:border-slate-700 pt-4 mt-4">
                  <h4 className="font-medium text-slate-900 dark:text-white mb-3">
                    {t('uriBlock.exceptionIPs')}
                  </h4>
                  <p className="text-sm text-slate-500 dark:text-slate-400 mb-3">
                    {t('uriBlock.global.exceptionIPsDesc', 'IPs that bypass global URI blocking.')}
                  </p>
                  <div className="flex gap-2 mb-3">
                    <input
                      type="text"
                      value={globalExceptionIP}
                      onChange={(e) => setGlobalExceptionIP(e.target.value)}
                      placeholder="192.168.1.100"
                      className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && globalExceptionIP.trim()) {
                          setPendingGlobalExceptionIPs([...effectiveGlobalExceptionIPs, globalExceptionIP.trim()])
                          setGlobalExceptionIP('')
                        }
                      }}
                    />
                    <button
                      onClick={() => {
                        if (globalExceptionIP.trim()) {
                          setPendingGlobalExceptionIPs([...effectiveGlobalExceptionIPs, globalExceptionIP.trim()])
                          setGlobalExceptionIP('')
                        }
                      }}
                      disabled={!globalExceptionIP.trim()}
                      className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
                    >
                      {t('common:add')}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {effectiveGlobalExceptionIPs.map(ip => (
                      <span key={ip} className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded">
                        {ip}
                        <button
                          onClick={() => {
                            setPendingGlobalExceptionIPs(effectiveGlobalExceptionIPs.filter(i => i !== ip))
                          }}
                          className="hover:text-green-600 dark:hover:text-green-300"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      </span>
                    ))}
                    {effectiveGlobalExceptionIPs.length === 0 && (
                      <span className="text-sm text-slate-500 dark:text-slate-400 italic">
                        {t('uriBlock.hostModal.noExceptionIPs')}
                      </span>
                    )}
                  </div>
                </div>

                {/* Allow Private IPs */}
                <div className="border-t border-slate-200 dark:border-slate-700 pt-4 mt-4">
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={effectiveGlobalAllowPrivate}
                      onChange={(e) => setPendingGlobalAllowPrivate(e.target.checked)}
                      className="w-4 h-4 rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                    />
                    <div>
                      <div className="text-sm font-medium text-slate-900 dark:text-white">
                        {t('uriBlock.allowPrivateIPs')}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">
                        {t('uriBlock.hostModal.allowPrivateIPsDesc')}
                      </div>
                    </div>
                  </label>
                </div>
              </div>

              {/* Info Box */}
              <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                <div className="flex gap-3">
                  <svg className="w-5 h-5 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div className="text-sm text-blue-800 dark:text-blue-300">
                    <p className="font-medium">{t('uriBlock.global.infoTitle', 'How Global Rules Work')}</p>
                    <p className="mt-1">{t('uriBlock.global.infoDesc', 'Global rules are automatically applied to all proxy hosts. They are checked before host-specific rules. Use this for common security patterns like blocking WordPress admin, XML-RPC, or sensitive files.')}</p>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Rules Tab Content */}
      {activeTab === 'rules' && (
        <>
          {/* Filters */}
          <div className="flex items-center gap-4">
            <select
              value={hostFilter}
              onChange={(e) => setHostFilter(e.target.value)}
              className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-900 dark:text-white text-sm"
            >
              <option value="all">{t('uriBlock.filters.allHosts')}</option>
              {hosts.map(host => (
                <option key={host} value={host}>{host}</option>
              ))}
            </select>
          </div>

          {/* Hosts List */}
      {filteredBlocks.length === 0 ? (
        <div className="text-center py-12 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700">
          <svg className="w-16 h-16 mx-auto text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
          <h3 className="mt-4 text-lg font-medium text-slate-900 dark:text-white">
            {t('uriBlock.empty.title')}
          </h3>
          <p className="mt-2 text-slate-500 dark:text-slate-400">
            {t('uriBlock.empty.description')}
          </p>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
          <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead className="bg-slate-50 dark:bg-slate-800/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('uriBlock.table.status')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('uriBlock.table.host')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('uriBlock.table.rules')}
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('uriBlock.table.settings')}
                </th>
                <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  {t('uriBlock.table.actions')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              {filteredBlocks.map(block => (
                <tr
                  key={block.id}
                  className="hover:bg-slate-50 dark:hover:bg-slate-700/50 cursor-pointer"
                  onClick={() => openHostModal(block)}
                >
                  <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => handleToggleEnabled(block)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        block.enabled && block.host_enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
                      }`}
                      disabled={updateMutation.isPending}
                    >
                      <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
                        block.enabled && block.host_enabled ? 'translate-x-6' : 'translate-x-1'
                      }`} />
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-slate-900 dark:text-white">
                      {block.domain_names[0]}
                    </div>
                    {block.domain_names.length > 1 && (
                      <div className="text-xs text-slate-500 dark:text-slate-400">
                        +{block.domain_names.length - 1} {t('uriBlock.moreHosts')}
                      </div>
                    )}
                    {!block.host_enabled && (
                      <span className="text-xs text-amber-600 dark:text-amber-400">
                        ({t('uriBlock.hostDisabled')})
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-100 dark:bg-rose-900/30 text-rose-800 dark:text-rose-400">
                      {block.rules.filter(r => r.enabled).length} {t('uriBlock.rulesCount')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
                    <div className="flex items-center gap-2">
                      {block.exception_ips.length > 0 && (
                        <span className="text-xs bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 px-2 py-0.5 rounded">
                          {block.exception_ips.length} {t('uriBlock.exceptions')}
                        </span>
                      )}
                      {block.allow_private_ips && (
                        <span className="text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 px-2 py-0.5 rounded">
                          {t('uriBlock.privateAllowed')}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => openHostModal(block)}
                        className="p-1.5 text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded transition-colors"
                        title={t('common:edit')}
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button
                        onClick={() => {
                          if (confirm(t('uriBlock.confirmDeleteHost', { host: block.domain_names[0] }) || `Are you sure you want to delete URI blocking for ${block.domain_names[0]}?`)) {
                            deleteURIBlockMutation.mutate(block.proxy_host_id);
                          }
                        }}
                        disabled={deleteURIBlockMutation.isPending}
                        className="p-1.5 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        title={t('common:delete')}
                      >
                        {deleteURIBlockMutation.isPending ? (
                          <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                          </svg>
                        ) : (
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
        </>
      )}

      {/* History Tab Content */}
      {activeTab === 'history' && (
        <div className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
          {historyLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-rose-600"></div>
            </div>
          ) : !historyData || historyData.length === 0 ? (
            <div className="text-center py-12">
              <svg className="w-16 h-16 mx-auto text-slate-300 dark:text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <h3 className="mt-4 text-lg font-medium text-slate-900 dark:text-white">
                {t('uriBlock.history.empty')}
              </h3>
            </div>
          ) : (
            <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
              <thead className="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    {t('uriBlock.history.time')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    {t('uriBlock.history.action')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    {t('uriBlock.history.host')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    {t('uriBlock.history.details')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                    {t('uriBlock.history.user')}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                {historyData.map((entry: URIBlockHistoryEntry) => (
                  <tr key={entry.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50">
                    <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300 whitespace-nowrap">
                      {formatDate(entry.created_at, i18n.language)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        entry.details?.action === 'add_rule'
                          ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                          : entry.details?.action === 'remove_rule'
                          ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                          : 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                      }`}>
                        {entry.details?.action === 'add_rule' && t('uriBlock.history.actions.addRule')}
                        {entry.details?.action === 'remove_rule' && t('uriBlock.history.actions.removeRule')}
                        {!entry.details?.action && (entry.details?.enabled ? t('uriBlock.history.actions.enabled') : t('uriBlock.history.actions.disabled'))}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-medium text-slate-900 dark:text-white">
                      {entry.details?.host || entry.details?.name || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                      {entry.details?.pattern && (
                        <span className="font-mono bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded text-xs">
                          {entry.details.pattern}
                        </span>
                      )}
                      {entry.details?.match_type && (
                        <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs ${getMatchTypeColor(entry.details.match_type as URIMatchType)}`}>
                          {getMatchTypeLabel(entry.details.match_type as URIMatchType, t)}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
                      {entry.user_email || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Host Detail Modal */}
      {editingBlock && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
                  {editingBlock.domain_names[0]}
                </h2>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  {t('uriBlock.hostModal.subtitle')}
                </p>
              </div>
              <button
                onClick={closeHostModal}
                className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg"
              >
                <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Enable Toggle */}
              <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
                <div>
                  <div className="font-medium text-slate-900 dark:text-white">
                    {t('uriBlock.hostModal.enableBlocking')}
                  </div>
                  <div className="text-sm text-slate-500 dark:text-slate-400">
                    {t('uriBlock.hostModal.enableBlockingDesc')}
                  </div>
                </div>
                <button
                  onClick={() => handleToggleEnabled(editingBlock)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    editingBlock.enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
                  }`}
                  disabled={updateMutation.isPending}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${
                    editingBlock.enabled ? 'translate-x-6' : 'translate-x-1'
                  }`} />
                </button>
              </div>

              {/* Rules Section */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-medium text-slate-900 dark:text-white">
                    {t('uriBlock.hostModal.rules')} ({editingBlock.rules.length})
                  </h3>
                  <button
                    onClick={() => setShowAddRuleForm(!showAddRuleForm)}
                    className="text-sm text-rose-600 hover:text-rose-700 dark:text-rose-400 font-medium flex items-center gap-1"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    {t('uriBlock.addRule')}
                  </button>
                </div>

                {/* Add Rule Form */}
                {showAddRuleForm && (
                  <div className="mb-4 p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg space-y-3">
                    <div className="grid grid-cols-3 gap-3">
                      <div className="col-span-2">
                        <input
                          type="text"
                          value={newPattern}
                          onChange={(e) => setNewPattern(e.target.value)}
                          placeholder={t('uriBlock.modal.patternPlaceholder')}
                          className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white font-mono text-sm"
                        />
                      </div>
                      <div>
                        <select
                          value={newMatchType}
                          onChange={(e) => setNewMatchType(e.target.value as URIMatchType)}
                          className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                        >
                          <option value="prefix">{t('uriBlock.matchTypes.prefix')}</option>
                          <option value="exact">{t('uriBlock.matchTypes.exact')}</option>
                          <option value="regex">{t('uriBlock.matchTypes.regex')}</option>
                        </select>
                      </div>
                    </div>
                    <div className="flex gap-3">
                      <input
                        type="text"
                        value={newDescription}
                        onChange={(e) => setNewDescription(e.target.value)}
                        placeholder={t('uriBlock.modal.descriptionPlaceholder')}
                        className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                      />
                      <button
                        onClick={handleAddRule}
                        disabled={!newPattern.trim() || addRuleMutation.isPending || bulkAddRuleMutation.isPending}
                        className="px-4 py-2 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
                      >
                        {(addRuleMutation.isPending || bulkAddRuleMutation.isPending) ? '...' : t('uriBlock.modal.addButton')}
                      </button>
                    </div>
                    {/* Apply to all hosts checkbox */}
                    <div className="flex items-center gap-2 pt-2">
                      <input
                        type="checkbox"
                        id="applyToAllHosts"
                        checked={applyToAllHosts}
                        onChange={(e) => setApplyToAllHosts(e.target.checked)}
                        className="w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-rose-600 focus:ring-rose-500"
                      />
                      <label htmlFor="applyToAllHosts" className="text-sm text-slate-700 dark:text-slate-300">
                        {t('uriBlock.bulkAdd.applyToAll')}
                      </label>
                      {applyToAllHosts && (
                        <span className="text-xs text-amber-600 dark:text-amber-400 ml-2">
                          ({t('uriBlock.bulkAdd.willApplyToAll', { count: proxyHosts.length })})
                        </span>
                      )}
                    </div>
                    {/* Quick Templates */}
                    <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-200 dark:border-slate-600">
                      <span className="text-xs text-slate-500 dark:text-slate-400">{t('uriBlock.modal.quickTemplates')}:</span>
                      {[
                        { p: '/wp-admin', t: 'prefix', d: 'Block WP Admin' },
                        { p: '/xmlrpc.php', t: 'exact', d: 'Block XML-RPC' },
                        { p: '/wp-login.php', t: 'exact', d: 'Block WP Login' },
                        { p: '\\.php$', t: 'regex', d: 'Block PHP' },
                        { p: '/.env', t: 'prefix', d: 'Block .env' },
                      ].map(({ p, t: type, d }) => (
                        <button
                          key={p}
                          onClick={() => { setNewPattern(p); setNewMatchType(type as URIMatchType); setNewDescription(d); }}
                          className="px-2 py-0.5 text-xs bg-slate-200 dark:bg-slate-600 text-slate-700 dark:text-slate-300 rounded hover:bg-slate-300 dark:hover:bg-slate-500"
                        >
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Rules List */}
                <div className="space-y-2">
                  {editingBlock.rules.length === 0 ? (
                    <p className="text-sm text-slate-500 dark:text-slate-400 italic py-4 text-center">
                      {t('uriBlock.noRules')}
                    </p>
                  ) : (
                    editingBlock.rules.map((rule: URIBlockRule) => (
                      <div
                        key={rule.id}
                        className={`flex items-center justify-between p-3 rounded-lg border ${
                          rule.enabled
                            ? 'bg-rose-50 dark:bg-rose-900/20 border-rose-200 dark:border-rose-800'
                            : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 opacity-60'
                        }`}
                      >
                        <div className="flex items-center gap-3 flex-1 min-w-0">
                          <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getMatchTypeColor(rule.match_type)}`}>
                            {getMatchTypeLabel(rule.match_type, t)}
                          </span>
                          <code className="font-mono text-sm text-slate-900 dark:text-white truncate">
                            {rule.pattern}
                          </code>
                          {rule.description && (
                            <span className="text-sm text-slate-500 dark:text-slate-400 truncate">
                              - {rule.description}
                            </span>
                          )}
                        </div>
                        <button
                          onClick={() => {
                            if (confirm(t('uriBlock.confirmDelete'))) {
                              removeRuleMutation.mutate({
                                proxyHostId: editingBlock.proxy_host_id,
                                ruleId: rule.id,
                              })
                            }
                          }}
                          className="p-1.5 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/30 rounded shrink-0"
                          disabled={removeRuleMutation.isPending}
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Exception IPs */}
              <div>
                <h3 className="font-medium text-slate-900 dark:text-white mb-3">
                  {t('uriBlock.exceptionIPs')}
                </h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mb-3">
                  {t('uriBlock.hostModal.exceptionIPsDesc')}
                </p>
                <div className="flex gap-2 mb-3">
                  <input
                    type="text"
                    value={newExceptionIP}
                    onChange={(e) => setNewExceptionIP(e.target.value)}
                    placeholder="192.168.1.100"
                    className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm"
                    onKeyDown={(e) => e.key === 'Enter' && handleAddExceptionIP()}
                  />
                  <button
                    onClick={handleAddExceptionIP}
                    disabled={!newExceptionIP.trim() || updateMutation.isPending}
                    className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium"
                  >
                    {t('common:add')}
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {editingBlock.exception_ips.map(ip => (
                    <span key={ip} className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded">
                      {ip}
                      <button
                        onClick={() => handleRemoveExceptionIP(ip)}
                        className="hover:text-green-600 dark:hover:text-green-300"
                      >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </span>
                  ))}
                  {editingBlock.exception_ips.length === 0 && (
                    <span className="text-sm text-slate-500 dark:text-slate-400 italic">
                      {t('uriBlock.hostModal.noExceptionIPs')}
                    </span>
                  )}
                </div>
              </div>

              {/* Settings */}
              <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
                <h3 className="font-medium text-slate-900 dark:text-white mb-3">
                  {t('uriBlock.hostModal.settings')}
                </h3>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editAllowPrivateIPs}
                    onChange={(e) => {
                      setEditAllowPrivateIPs(e.target.checked)
                      if (editingBlock) {
                        updateMutation.mutate({
                          proxyHostId: editingBlock.proxy_host_id,
                          data: {
                            enabled: editingBlock.enabled,
                            rules: editingBlock.rules,
                            exception_ips: editingBlock.exception_ips,
                            allow_private_ips: e.target.checked,
                          },
                        })
                      }
                    }}
                    className="w-4 h-4 rounded border-slate-300 text-primary-600 focus:ring-primary-500"
                  />
                  <div>
                    <div className="text-sm font-medium text-slate-900 dark:text-white">
                      {t('uriBlock.allowPrivateIPs')}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      {t('uriBlock.hostModal.allowPrivateIPsDesc')}
                    </div>
                  </div>
                </label>
              </div>

              {/* Info */}
              <div className="text-xs text-slate-500 dark:text-slate-400 border-t border-slate-200 dark:border-slate-700 pt-4">
                {t('uriBlock.updatedAt')}: {formatDate(editingBlock.updated_at, i18n.language)}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 flex justify-between">
              <button
                onClick={() => {
                  if (confirm(t('uriBlock.confirmDeleteHost', { host: editingBlock.domain_names[0] }) || `Are you sure you want to delete URI blocking for ${editingBlock.domain_names[0]}? This action cannot be undone.`)) {
                    deleteURIBlockMutation.mutate(editingBlock.proxy_host_id);
                  }
                }}
                disabled={deleteURIBlockMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors flex items-center gap-2"
              >
                {deleteURIBlockMutation.isPending && (
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                )}
                {t('common:delete')}
              </button>
              <button
                onClick={closeHostModal}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 rounded-lg font-medium transition-colors"
              >
                {t('common:close')}
              </button>
            </div>
          </div>
        </div>
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

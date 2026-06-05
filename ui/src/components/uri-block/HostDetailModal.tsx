import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  updateURIBlock,
  removeURIBlockRule,
  addURIBlockRule,
  bulkAddURIBlockRule,
  deleteURIBlock,
  type URIBlockWithHost,
} from '../../api/security'
import type { URIBlockRule, URIMatchType, AddURIBlockRuleRequest } from '../../types/security'
import { ModalShell } from '../common/ModalShell'

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

function formatDate(dateStr: string, locale?: string): string {
  return new Date(dateStr).toLocaleString(locale || 'ko-KR')
}

interface HostDetailModalProps {
  block: URIBlockWithHost
  proxyHostsCount: number
  onClose: () => void
}

export function HostDetailModal({ block: editingBlock, proxyHostsCount, onClose }: HostDetailModalProps) {
  const { t, i18n } = useTranslation('waf')
  const queryClient = useQueryClient()
  const [showAddRuleForm, setShowAddRuleForm] = useState(false)
  const [newPattern, setNewPattern] = useState('')
  const [newMatchType, setNewMatchType] = useState<URIMatchType>('prefix')
  const [newDescription, setNewDescription] = useState('')
  const [applyToAllHosts, setApplyToAllHosts] = useState(false)
  const [editAllowPrivateIPs, setEditAllowPrivateIPs] = useState(editingBlock.allow_private_ips)
  const [newExceptionIP, setNewExceptionIP] = useState('')

  const updateMutation = useMutation({
    mutationFn: async ({ proxyHostId, data }: { proxyHostId: string; data: { enabled: boolean; rules: URIBlockRule[]; exception_ips: string[]; allow_private_ips: boolean } }) => updateURIBlock(proxyHostId, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['uri-blocks'] }) },
  })

  const removeRuleMutation = useMutation({
    mutationFn: async ({ proxyHostId, ruleId }: { proxyHostId: string; ruleId: string }) => removeURIBlockRule(proxyHostId, ruleId),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['uri-blocks'] }) },
  })

  const addRuleMutation = useMutation({
    mutationFn: async ({ proxyHostId, rule }: { proxyHostId: string; rule: AddURIBlockRuleRequest }) => addURIBlockRule(proxyHostId, rule),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['uri-blocks'] }); resetAddRuleForm() },
  })

  const bulkAddRuleMutation = useMutation({
    mutationFn: async (rule: { pattern: string; match_type: URIMatchType; description?: string }) => bulkAddURIBlockRule({ pattern: rule.pattern, match_type: rule.match_type, description: rule.description }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
      queryClient.invalidateQueries({ queryKey: ['uri-block-history'] })
      resetAddRuleForm()
      alert(t('uriBlock.bulkAdd.success', { count: data.added_count, total: data.total_hosts }))
    },
    onError: (error) => { alert(t('uriBlock.bulkAdd.failed', { error: (error as Error).message })) },
  })

  const deleteURIBlockMutation = useMutation({
    mutationFn: async (proxyHostId: string) => deleteURIBlock(proxyHostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uri-blocks'] })
      queryClient.invalidateQueries({ queryKey: ['uri-block-history'] })
      onClose()
    },
    onError: (error) => { alert(t('common:error') + ': ' + (error instanceof Error ? error.message : 'Unknown error')) },
  })

  const resetAddRuleForm = () => { setNewPattern(''); setNewMatchType('prefix'); setNewDescription(''); setApplyToAllHosts(false) }

  const handleAddRule = () => {
    if (!newPattern.trim()) return
    if (applyToAllHosts) {
      bulkAddRuleMutation.mutate({ pattern: newPattern.trim(), match_type: newMatchType, description: newDescription.trim() || undefined })
    } else {
      addRuleMutation.mutate({ proxyHostId: editingBlock.proxy_host_id, rule: { pattern: newPattern.trim(), match_type: newMatchType, description: newDescription.trim() || undefined, enabled: true } })
    }
  }

  const handleToggleEnabled = () => {
    updateMutation.mutate({ proxyHostId: editingBlock.proxy_host_id, data: { enabled: !editingBlock.enabled, rules: editingBlock.rules, exception_ips: editingBlock.exception_ips, allow_private_ips: editingBlock.allow_private_ips } })
  }

  const handleAddExceptionIP = () => {
    if (!newExceptionIP.trim()) return
    const newIPs = [...editingBlock.exception_ips, newExceptionIP.trim()]
    updateMutation.mutate({ proxyHostId: editingBlock.proxy_host_id, data: { enabled: editingBlock.enabled, rules: editingBlock.rules, exception_ips: newIPs, allow_private_ips: editingBlock.allow_private_ips } })
    setNewExceptionIP('')
  }

  const handleRemoveExceptionIP = (ip: string) => {
    const newIPs = editingBlock.exception_ips.filter(i => i !== ip)
    updateMutation.mutate({ proxyHostId: editingBlock.proxy_host_id, data: { enabled: editingBlock.enabled, rules: editingBlock.rules, exception_ips: newIPs, allow_private_ips: editingBlock.allow_private_ips } })
  }

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-2xl">
      <div className="flex flex-col max-h-[90vh]">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{editingBlock.domain_names[0]}</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">{t('uriBlock.hostModal.subtitle')}</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg">
            <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Enable Toggle */}
          <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
            <div>
              <div className="font-medium text-slate-900 dark:text-white">{t('uriBlock.hostModal.enableBlocking')}</div>
              <div className="text-sm text-slate-500 dark:text-slate-400">{t('uriBlock.hostModal.enableBlockingDesc')}</div>
            </div>
            <button onClick={handleToggleEnabled} className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${editingBlock.enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'}`} disabled={updateMutation.isPending}>
              <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${editingBlock.enabled ? 'translate-x-6' : 'translate-x-1'}`} />
            </button>
          </div>

          {/* Rules Section */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-medium text-slate-900 dark:text-white">{t('uriBlock.hostModal.rules')} ({editingBlock.rules.length})</h3>
              <button onClick={() => setShowAddRuleForm(!showAddRuleForm)} className="text-sm text-rose-600 hover:text-rose-700 dark:text-rose-400 font-medium flex items-center gap-1">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
                {t('uriBlock.addRule')}
              </button>
            </div>

            {showAddRuleForm && (
              <div className="mb-4 p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg space-y-3">
                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2">
                    <input type="text" value={newPattern} onChange={(e) => setNewPattern(e.target.value)} placeholder={t('uriBlock.modal.patternPlaceholder')} className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white font-mono text-sm" />
                  </div>
                  <div>
                    <select value={newMatchType} onChange={(e) => setNewMatchType(e.target.value as URIMatchType)} className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm">
                      <option value="prefix">{t('uriBlock.matchTypes.prefix')}</option>
                      <option value="exact">{t('uriBlock.matchTypes.exact')}</option>
                      <option value="regex">{t('uriBlock.matchTypes.regex')}</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-3">
                  <input type="text" value={newDescription} onChange={(e) => setNewDescription(e.target.value)} placeholder={t('uriBlock.modal.descriptionPlaceholder')} className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm" />
                  <button onClick={handleAddRule} disabled={!newPattern.trim() || addRuleMutation.isPending || bulkAddRuleMutation.isPending} className="px-4 py-2 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">
                    {(addRuleMutation.isPending || bulkAddRuleMutation.isPending) ? '...' : t('uriBlock.modal.addButton')}
                  </button>
                </div>
                <div className="flex items-center gap-2 pt-2">
                  <input type="checkbox" id="applyToAllHosts" checked={applyToAllHosts} onChange={(e) => setApplyToAllHosts(e.target.checked)} className="w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-rose-600 focus:ring-rose-500" />
                  <label htmlFor="applyToAllHosts" className="text-sm text-slate-700 dark:text-slate-300">{t('uriBlock.bulkAdd.applyToAll')}</label>
                  {applyToAllHosts && (<span className="text-xs text-amber-600 dark:text-amber-400 ml-2">({t('uriBlock.bulkAdd.willApplyToAll', { count: proxyHostsCount })})</span>)}
                </div>
                <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-200 dark:border-slate-600">
                  <span className="text-xs text-slate-500 dark:text-slate-400">{t('uriBlock.modal.quickTemplates')}:</span>
                  {[
                    { p: '/wp-admin', t: 'prefix', d: t('uriBlock.templates.wpAdmin') }, { p: '/xmlrpc.php', t: 'exact', d: t('uriBlock.templates.xmlrpc') },
                    { p: '/wp-login.php', t: 'exact', d: t('uriBlock.templates.wpLogin') }, { p: '\\.php$', t: 'regex', d: t('uriBlock.templates.php') }, { p: '/.env', t: 'prefix', d: t('uriBlock.templates.env') },
                  ].map(({ p, t: type, d }) => (
                    <button key={p} onClick={() => { setNewPattern(p); setNewMatchType(type as URIMatchType); setNewDescription(d); }} className="px-2 py-0.5 text-xs bg-slate-200 dark:bg-slate-600 text-slate-700 dark:text-slate-300 rounded hover:bg-slate-300 dark:hover:bg-slate-500">{p}</button>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-2">
              {editingBlock.rules.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400 italic py-4 text-center">{t('uriBlock.noRules')}</p>
              ) : (
                editingBlock.rules.map((rule: URIBlockRule) => (
                  <div key={rule.id} className={`flex items-center justify-between p-3 rounded-lg border ${rule.enabled ? 'bg-rose-50 dark:bg-rose-900/20 border-rose-200 dark:border-rose-800' : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 opacity-60'}`}>
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getMatchTypeColor(rule.match_type)}`}>{getMatchTypeLabel(rule.match_type, t)}</span>
                      <code className="font-mono text-sm text-slate-900 dark:text-white truncate">{rule.pattern}</code>
                      {rule.description && (<span className="text-sm text-slate-500 dark:text-slate-400 truncate">- {rule.description}</span>)}
                    </div>
                    <button onClick={() => { if (confirm(t('uriBlock.confirmDelete'))) { removeRuleMutation.mutate({ proxyHostId: editingBlock.proxy_host_id, ruleId: rule.id }) } }} className="p-1.5 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/30 rounded shrink-0" disabled={removeRuleMutation.isPending}>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Exception IPs */}
          <div>
            <h3 className="font-medium text-slate-900 dark:text-white mb-3">{t('uriBlock.exceptionIPs')}</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-3">{t('uriBlock.hostModal.exceptionIPsDesc')}</p>
            <div className="flex gap-2 mb-3">
              <input type="text" value={newExceptionIP} onChange={(e) => setNewExceptionIP(e.target.value)} placeholder="192.168.1.100" className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm" onKeyDown={(e) => e.key === 'Enter' && handleAddExceptionIP()} />
              <button onClick={handleAddExceptionIP} disabled={!newExceptionIP.trim() || updateMutation.isPending} className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium">{t('common:add')}</button>
            </div>
            <div className="flex flex-wrap gap-2">
              {editingBlock.exception_ips.map(ip => (
                <span key={ip} className="inline-flex items-center gap-1 px-2 py-1 text-sm bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400 rounded">
                  {ip}
                  <button onClick={() => handleRemoveExceptionIP(ip)} className="hover:text-green-600 dark:hover:text-green-300">
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  </button>
                </span>
              ))}
              {editingBlock.exception_ips.length === 0 && (<span className="text-sm text-slate-500 dark:text-slate-400 italic">{t('uriBlock.hostModal.noExceptionIPs')}</span>)}
            </div>
          </div>

          {/* Settings */}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <h3 className="font-medium text-slate-900 dark:text-white mb-3">{t('uriBlock.hostModal.settings')}</h3>
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={editAllowPrivateIPs} onChange={(e) => {
                setEditAllowPrivateIPs(e.target.checked)
                updateMutation.mutate({ proxyHostId: editingBlock.proxy_host_id, data: { enabled: editingBlock.enabled, rules: editingBlock.rules, exception_ips: editingBlock.exception_ips, allow_private_ips: e.target.checked } })
              }} className="w-4 h-4 rounded border-slate-300 text-primary-600 focus:ring-primary-500" />
              <div>
                <div className="text-sm font-medium text-slate-900 dark:text-white">{t('uriBlock.allowPrivateIPs')}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{t('uriBlock.hostModal.allowPrivateIPsDesc')}</div>
              </div>
            </label>
          </div>

          <div className="text-xs text-slate-500 dark:text-slate-400 border-t border-slate-200 dark:border-slate-700 pt-4">{t('uriBlock.updatedAt')}: {formatDate(editingBlock.updated_at, i18n.language)}</div>
        </div>

        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 flex justify-between">
          <button onClick={() => { if (confirm(t('uriBlock.confirmDeleteHost', { host: editingBlock.domain_names[0] }) || `Are you sure?`)) { deleteURIBlockMutation.mutate(editingBlock.proxy_host_id) } }} disabled={deleteURIBlockMutation.isPending} className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg font-medium transition-colors flex items-center gap-2">
            {deleteURIBlockMutation.isPending && (<svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" /></svg>)}
            {t('common:delete')}
          </button>
          <button onClick={onClose} className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 rounded-lg font-medium transition-colors">{t('common:buttons.close')}</button>
        </div>
      </div>
    </ModalShell>
  )
}

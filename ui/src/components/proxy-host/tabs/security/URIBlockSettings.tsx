import { useState } from 'react'
import type { URIBlockState } from '../../types'
import type { URIBlockRule, URIMatchType } from '../../../../types/security'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../../common/HelpTip'

interface URIBlockSettingsProps {
  uriBlockData: URIBlockState
  setURIBlockData: React.Dispatch<React.SetStateAction<URIBlockState>>
}

// Quick add patterns
const QUICK_PATTERNS = [
  { pattern: '/wp-admin', match_type: 'prefix' as URIMatchType, description: 'WordPress Admin' },
  { pattern: '/wp-login.php', match_type: 'exact' as URIMatchType, description: 'WordPress Login' },
  { pattern: '/xmlrpc.php', match_type: 'exact' as URIMatchType, description: 'WordPress XML-RPC' },
  { pattern: '/.env', match_type: 'exact' as URIMatchType, description: 'Environment File' },
  { pattern: '/.git', match_type: 'prefix' as URIMatchType, description: 'Git Directory' },
  { pattern: '/phpmyadmin', match_type: 'prefix' as URIMatchType, description: 'phpMyAdmin' },
]

export function URIBlockSettings({ uriBlockData, setURIBlockData }: URIBlockSettingsProps) {
  const { t } = useTranslation('proxyHost')
  const [newPattern, setNewPattern] = useState('')
  const [newMatchType, setNewMatchType] = useState<URIMatchType>('prefix')
  const [newDescription, setNewDescription] = useState('')
  const [exceptionIPsInput, setExceptionIPsInput] = useState(
    (uriBlockData.exception_ips || []).join('\n')
  )

  const addRule = () => {
    if (!newPattern.trim()) return

    const newRule: URIBlockRule = {
      id: crypto.randomUUID(),
      pattern: newPattern.trim(),
      match_type: newMatchType,
      description: newDescription.trim() || undefined,
      enabled: true,
    }

    setURIBlockData((prev) => ({
      ...prev,
      rules: [...(prev.rules || []), newRule],
    }))

    setNewPattern('')
    setNewDescription('')
  }

  const removeRule = (ruleId: string) => {
    setURIBlockData((prev) => ({
      ...prev,
      rules: (prev.rules || []).filter((r) => r.id !== ruleId),
    }))
  }

  const toggleRule = (ruleId: string) => {
    setURIBlockData((prev) => ({
      ...prev,
      rules: (prev.rules || []).map((r) =>
        r.id === ruleId ? { ...r, enabled: !r.enabled } : r
      ),
    }))
  }

  const addQuickPattern = (pattern: string, matchType: URIMatchType, description: string) => {
    // Check if already exists
    const exists = (uriBlockData.rules || []).some(
      (r) => r.pattern === pattern && r.match_type === matchType
    )
    if (exists) return

    const newRule: URIBlockRule = {
      id: crypto.randomUUID(),
      pattern,
      match_type: matchType,
      description,
      enabled: true,
    }

    setURIBlockData((prev) => ({
      ...prev,
      rules: [...(prev.rules || []), newRule],
    }))
  }

  const updateExceptionIPs = (value: string) => {
    setExceptionIPsInput(value)
    const ips = value
      .split('\n')
      .map((ip) => ip.trim())
      .filter((ip) => ip)
    setURIBlockData((prev) => ({
      ...prev,
      exception_ips: ips,
    }))
  }

  const getMatchTypeLabel = (matchType: URIMatchType) => {
    switch (matchType) {
      case 'exact':
        return t('form.security.uriBlock.matchTypes.exact')
      case 'prefix':
        return t('form.security.uriBlock.matchTypes.prefix')
      case 'regex':
        return t('form.security.uriBlock.matchTypes.regex')
      default:
        return matchType
    }
  }

  const getMatchTypeBadgeColor = (matchType: URIMatchType) => {
    switch (matchType) {
      case 'exact':
        return 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
      case 'prefix':
        return 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
      case 'regex':
        return 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300'
      default:
        return 'bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300'
    }
  }

  return (
    <div
      className={`p-4 rounded-lg border-2 transition-colors ${
        uriBlockData.enabled
          ? 'bg-rose-50 dark:bg-rose-900/20 border-rose-200 dark:border-rose-800'
          : 'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'
      }`}
    >
      <label className="flex items-center justify-between cursor-pointer">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-full flex items-center justify-center ${
              uriBlockData.enabled
                ? 'bg-rose-100 dark:bg-rose-900/40'
                : 'bg-slate-200 dark:bg-slate-700'
            }`}
          >
            <svg
              className={`w-5 h-5 ${
                uriBlockData.enabled
                  ? 'text-rose-600 dark:text-rose-400'
                  : 'text-slate-400 dark:text-slate-500'
              }`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
              />
            </svg>
          </div>
          <div>
            <span className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
              {t('form.security.uriBlock.title')}
              <HelpTip contentKey="help.security.uriBlock" />
            </span>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {t('form.security.uriBlock.description')}
            </p>
          </div>
        </div>
        <input
          type="checkbox"
          checked={uriBlockData.enabled}
          onChange={(e) =>
            setURIBlockData((prev) => ({
              ...prev,
              enabled: e.target.checked,
            }))
          }
          className="rounded border-slate-300 dark:border-slate-600 text-rose-600 focus:ring-rose-500 h-5 w-5 dark:bg-slate-700"
        />
      </label>

      {uriBlockData.enabled && (
        <div className="mt-4 ml-13 pl-4 border-l-2 border-rose-200 dark:border-rose-800 space-y-4">
          {/* Quick add buttons */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('form.security.uriBlock.quickAdd')}
            </label>
            <div className="flex flex-wrap gap-2">
              {QUICK_PATTERNS.map((qp) => {
                const exists = (uriBlockData.rules || []).some(
                  (r) => r.pattern === qp.pattern && r.match_type === qp.match_type
                )
                return (
                  <button
                    key={qp.pattern}
                    type="button"
                    disabled={exists}
                    onClick={() => addQuickPattern(qp.pattern, qp.match_type, qp.description)}
                    className={`px-3 py-1 text-xs rounded-full transition-colors ${
                      exists
                        ? 'bg-slate-100 text-slate-400 cursor-not-allowed dark:bg-slate-700 dark:text-slate-500'
                        : 'bg-rose-100 text-rose-700 hover:bg-rose-200 dark:bg-rose-900/40 dark:text-rose-300 dark:hover:bg-rose-900/60'
                    }`}
                  >
                    {qp.description}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Add new rule */}
          <div className="bg-white dark:bg-slate-800 rounded-lg p-3 border border-slate-200 dark:border-slate-700">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              {t('form.security.uriBlock.addRule')}
            </label>
            <div className="space-y-2">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newPattern}
                  onChange={(e) => setNewPattern(e.target.value)}
                  placeholder={t('form.security.uriBlock.patternPlaceholder')}
                  className="flex-1 rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors dark:bg-slate-700 dark:text-white"
                />
                <select
                  value={newMatchType}
                  onChange={(e) => setNewMatchType(e.target.value as URIMatchType)}
                  className="rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors dark:bg-slate-700 dark:text-white"
                >
                  <option value="exact">{t('form.security.uriBlock.matchTypes.exact')}</option>
                  <option value="prefix">{t('form.security.uriBlock.matchTypes.prefix')}</option>
                  <option value="regex">{t('form.security.uriBlock.matchTypes.regex')}</option>
                </select>
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder={t('form.security.uriBlock.descriptionPlaceholder')}
                  className="flex-1 rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors dark:bg-slate-700 dark:text-white"
                />
                <button
                  type="button"
                  onClick={addRule}
                  disabled={!newPattern.trim()}
                  className="px-4 py-2 bg-rose-600 text-white rounded-lg hover:bg-rose-700 disabled:bg-slate-300 disabled:cursor-not-allowed text-sm font-medium transition-colors"
                >
                  {t('form.security.uriBlock.add')}
                </button>
              </div>
            </div>
          </div>

          {/* Rules list */}
          {(uriBlockData.rules || []).length > 0 && (
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                {t('form.security.uriBlock.rules')} ({(uriBlockData.rules || []).length})
              </label>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {(uriBlockData.rules || []).map((rule) => (
                  <div
                    key={rule.id}
                    className={`flex items-center justify-between p-2 rounded-lg border transition-colors ${
                      rule.enabled
                        ? 'bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700'
                        : 'bg-slate-50 dark:bg-slate-800/50 border-slate-100 dark:border-slate-700/50 opacity-60'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={() => toggleRule(rule.id)}
                        className="rounded border-slate-300 dark:border-slate-600 text-rose-600 focus:ring-rose-500 dark:bg-slate-700"
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <code className="text-sm font-mono text-slate-900 dark:text-white truncate">
                            {rule.pattern}
                          </code>
                          <span
                            className={`px-2 py-0.5 text-xs rounded-full ${getMatchTypeBadgeColor(
                              rule.match_type
                            )}`}
                          >
                            {getMatchTypeLabel(rule.match_type)}
                          </span>
                        </div>
                        {rule.description && (
                          <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                            {rule.description}
                          </p>
                        )}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => removeRule(rule.id)}
                      className="p-1 text-slate-400 hover:text-red-500 transition-colors"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M6 18L18 6M6 6l12 12"
                        />
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Exception IPs */}
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('form.security.uriBlock.exceptionIPs')}
            </label>
            <textarea
              value={exceptionIPsInput}
              onChange={(e) => updateExceptionIPs(e.target.value)}
              placeholder={t('form.security.uriBlock.exceptionIPsPlaceholder')}
              rows={3}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors dark:bg-slate-700 dark:text-white"
            />
          </div>

          {/* Allow private IPs */}
          <label className="flex items-center gap-2 cursor-pointer p-2 rounded-lg hover:bg-rose-100/50 dark:hover:bg-rose-900/30 transition-colors">
            <input
              type="checkbox"
              checked={uriBlockData.allow_private_ips ?? true}
              onChange={(e) =>
                setURIBlockData((prev) => ({
                  ...prev,
                  allow_private_ips: e.target.checked,
                }))
              }
              className="rounded border-slate-300 dark:border-slate-600 text-green-600 focus:ring-green-500 dark:bg-slate-700"
            />
            <div>
              <span className="text-sm text-slate-700 dark:text-slate-300 font-medium">
                {t('form.security.uriBlock.allowPrivateIPs')}
              </span>
              <p className="text-xs text-slate-400 dark:text-slate-500">
                {t('form.security.uriBlock.allowPrivateIPsDescription')}
              </p>
            </div>
          </label>
        </div>
      )}
    </div>
  )
}

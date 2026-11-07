import { useTranslation } from 'react-i18next';
import type { URIMatchType } from '../../types/security';
import type { GlobalURIBlock } from '../../api/security';
import { DnsHostnamesField, type DnsListDomains } from '../common/dns/DnsHostnamesField';
import { RuleExceptionIPs } from './RuleExceptionIPs';

function getMatchTypeColor(matchType: URIMatchType): string {
  switch (matchType) {
    case 'exact': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
    case 'prefix': return 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400'
    case 'regex': return 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400'
    default: return 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300'
  }
}

function getMatchTypeLabel(matchType: URIMatchType, t: (key: string) => string): string {
  switch (matchType) {
    case 'exact': return t('uriBlock.matchTypes.exact')
    case 'prefix': return t('uriBlock.matchTypes.prefix')
    case 'regex': return t('uriBlock.matchTypes.regex')
    default: return matchType
  }
}

interface GlobalTabProps {
  globalLoading: boolean;
  globalSaveMessage: { type: 'success' | 'error'; message: string } | null;
  hasGlobalPendingChanges: boolean;
  effectiveGlobalEnabled: boolean;
  effectiveGlobalAllowPrivate: boolean;
  effectiveGlobalExceptionIPs: string[];
  effectiveGlobalRules: GlobalURIBlock['rules'];
  updateGlobalIsPending: boolean;
  showGlobalAddForm: boolean;
  setShowGlobalAddForm: (v: boolean) => void;
  globalPattern: string;
  setGlobalPattern: (v: string) => void;
  globalMatchType: URIMatchType;
  setGlobalMatchType: (v: URIMatchType) => void;
  globalDescription: string;
  setGlobalDescription: (v: string) => void;
  globalExceptionIP: string;
  setGlobalExceptionIP: (v: string) => void;
  setPendingGlobalEnabled: (v: boolean) => void;
  setPendingGlobalAllowPrivate: (v: boolean) => void;
  setPendingGlobalExceptionIPs: (v: string[]) => void;
  setPendingGlobalRules: (v: GlobalURIBlock['rules']) => void;
  /** The exception domains as edited (#320), and their state, permission and confirm route. */
  globalExceptionHostnames: string[];
  setPendingGlobalExceptionHostnames: (v: string[]) => void;
  globalDomains: DnsListDomains;
  handleSaveGlobalChanges: () => void;
  handleDiscardGlobalChanges: () => void;
}

export function GlobalTab({
  globalLoading,
  globalSaveMessage,
  hasGlobalPendingChanges,
  effectiveGlobalEnabled,
  effectiveGlobalAllowPrivate,
  effectiveGlobalExceptionIPs,
  effectiveGlobalRules,
  updateGlobalIsPending,
  showGlobalAddForm,
  setShowGlobalAddForm,
  globalPattern,
  setGlobalPattern,
  globalMatchType,
  setGlobalMatchType,
  globalDescription,
  setGlobalDescription,
  globalExceptionIP,
  setGlobalExceptionIP,
  setPendingGlobalEnabled,
  setPendingGlobalAllowPrivate,
  setPendingGlobalExceptionIPs,
  setPendingGlobalRules,
  globalExceptionHostnames,
  setPendingGlobalExceptionHostnames,
  globalDomains,
  handleSaveGlobalChanges,
  handleDiscardGlobalChanges,
}: GlobalTabProps) {
  const { t } = useTranslation(['waf', 'dnsEntries']);

  if (globalLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-rose-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
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
              disabled={updateGlobalIsPending}
              className="px-4 py-1.5 text-sm bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded font-medium transition-colors flex items-center gap-2"
            >
              {updateGlobalIsPending && (
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
                      const newRule = {
                        id: `temp-${Date.now()}`,
                        pattern: globalPattern.trim(),
                        match_type: globalMatchType,
                        description: globalDescription.trim() || undefined,
                        enabled: true,
                      }
                      setPendingGlobalRules([...effectiveGlobalRules, newRule])
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
                  className={`flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg border ${
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
                  {/* A rule's own exception IPs (#343) join the pending rules, saved with the rest. */}
                  <RuleExceptionIPs
                    ips={rule.exception_ips}
                    onSave={(ips) =>
                      setPendingGlobalRules(effectiveGlobalRules.map((r) => (r.id === rule.id ? { ...r, exception_ips: ips } : r)))
                    }
                  />
                  <button
                    onClick={() => {
                      if (confirm(t('uriBlock.confirmDelete'))) {
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

        {/* Global Exception Domains (#320) */}
        <div className="border-t border-slate-200 dark:border-slate-700 pt-4 mt-4">
          <DnsHostnamesField
            {...globalDomains}
            names={globalExceptionHostnames}
            onChange={setPendingGlobalExceptionHostnames}
            note={t('dnsEntries:notes.uriBlock')}
          />
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
    </div>
  );
}

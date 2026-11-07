import { useState } from 'react'
import { useTranslation } from 'react-i18next'

interface RuleExceptionIPsProps {
  ips: string[] | undefined
  /** Saves the rule's list. A rejection is shown under the field, which stays open. */
  onSave: (ips: string[]) => void | Promise<unknown>
}

/**
 * A URI block rule's own exception IPs (#343): addresses only this rule lets
 * through. A chip on the rule's row shows how many there are, and opens the
 * list below the row, one address or CIDR range per line. Place it in a
 * flex-wrap row: the open list takes a line of its own at the end of it.
 */
export function RuleExceptionIPs({ ips, onSave }: RuleExceptionIPsProps) {
  const { t } = useTranslation(['waf', 'common'])
  const list = ips ?? []
  const [draft, setDraft] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const save = async () => {
    const next = (draft ?? '')
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean)
    setSaving(true)
    setError(null)
    try {
      await onSave(next)
      setDraft(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setDraft(draft === null ? list.join('\n') : null)
          setError(null)
        }}
        title={list.length > 0 ? list.join(', ') : t('uriBlock.ruleExceptions.title')}
        className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 transition-colors ${
          list.length > 0
            ? 'bg-green-100 text-green-800 hover:bg-green-200 dark:bg-green-900/30 dark:text-green-400 dark:hover:bg-green-900/50'
            : 'text-slate-500 hover:bg-slate-200 dark:text-slate-400 dark:hover:bg-slate-700'
        }`}
      >
        {list.length > 0
          ? t('uriBlock.ruleExceptions.count', { count: list.length })
          : t('uriBlock.ruleExceptions.add')}
      </button>
      {draft !== null && (
        <div className="order-last w-full space-y-2 pt-2">
          <label className="block text-xs font-medium text-slate-700 dark:text-slate-300">
            {t('uriBlock.ruleExceptions.label')}
          </label>
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={3}
            placeholder={'203.0.113.5\n198.51.100.0/24'}
            className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30"
          />
          <p className="text-xs text-slate-500 dark:text-slate-400">{t('uriBlock.ruleExceptions.help')}</p>
          {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setDraft(null)
                setError(null)
              }}
              disabled={saving}
              className="px-3 py-1.5 text-sm rounded-lg text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700"
            >
              {t('common:buttons.cancel')}
            </button>
            <button
              type="button"
              onClick={save}
              disabled={saving}
              className="px-3 py-1.5 text-sm rounded-lg bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white font-medium"
            >
              {t('common:buttons.apply')}
            </button>
          </div>
        </div>
      )}
    </>
  )
}

import { useId, useState, type KeyboardEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { XIcon } from '../common/listui'

// Mirrors model.NormalizeTags on the server: the server stays the authority,
// this only keeps obviously-wrong input from round-tripping to a 400.
export const MAX_TAGS = 10
export const MAX_TAG_LENGTH = 32
const TAG_RE = /^[a-z0-9][a-z0-9._-]*$/

interface TagInputProps {
  value: string[]
  onChange: (tags: string[]) => void
  suggestions?: string[]
  disabled?: boolean
  /** Lets the section's <label htmlFor> point at the input. */
  id?: string
}

export function TagInput({ value, onChange, suggestions = [], disabled, id }: TagInputProps) {
  const { t } = useTranslation('proxyHost')
  const listId = useId()
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)

  const commit = () => {
    const tag = draft.trim().toLowerCase()
    if (!tag) return
    if (tag.length > MAX_TAG_LENGTH || !TAG_RE.test(tag)) {
      setError(t('form.basic.tagsInvalid'))
      return
    }
    if (value.includes(tag)) {
      setDraft('')
      return
    }
    if (value.length >= MAX_TAGS) {
      setError(t('form.basic.tagsMax', { max: MAX_TAGS }))
      return
    }
    onChange([...value, tag])
    setDraft('')
    setError(null)
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      commit()
    } else if (e.key === 'Backspace' && draft === '' && value.length > 0) {
      onChange(value.slice(0, -1))
    }
  }

  return (
    <div>
      <div className="flex flex-wrap gap-1.5 mb-2" data-testid="tag-chips">
        {value.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 rounded-full bg-primary-50 dark:bg-primary-900/30 text-primary-700 dark:text-primary-300 px-2.5 py-0.5 text-xs font-medium"
          >
            {tag}
            {!disabled && (
              <button
                type="button"
                onClick={() => onChange(value.filter((v) => v !== tag))}
                className="rounded-full p-0.5 hover:bg-primary-100 dark:hover:bg-primary-800/50"
                aria-label={t('form.basic.tagRemove', { tag })}
              >
                <XIcon />
              </button>
            )}
          </span>
        ))}
      </div>
      <input
        id={id}
        type="text"
        value={draft}
        disabled={disabled}
        list={listId}
        onChange={(e) => {
          setDraft(e.target.value)
          setError(null)
        }}
        onKeyDown={onKeyDown}
        onBlur={commit}
        placeholder={t('form.basic.tagsPlaceholder')}
        maxLength={MAX_TAG_LENGTH}
        data-testid="tag-input"
        className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-primary-500 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
      />
      <datalist id={listId}>
        {suggestions
          .filter((s) => !value.includes(s))
          .map((s) => (
            <option key={s} value={s} />
          ))}
      </datalist>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
        {t('form.basic.tagsHelp', { max: MAX_TAGS })}
      </p>
      {error && <p className="mt-1 text-sm text-red-600 dark:text-red-400">{error}</p>}
    </div>
  )
}

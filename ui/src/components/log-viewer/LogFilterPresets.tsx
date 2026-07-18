import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  fetchLogFilterPresets,
  createLogFilterPreset,
  deleteLogFilterPreset,
} from '../../api/log-filter-presets'
import type { LogFilter, LogType } from '../../types/log'

interface LogFilterPresetsProps {
  logType: LogType
  currentFilter: LogFilter
  onLoad: (filter: LogFilter) => void
}

// Save / load / delete named sets of log-viewer filters (#210), so an operator
// can e.g. keep a "hide internal subnet + monitoring host" filter and re-apply
// it in one click instead of re-typing the exclude filters each time.
export function LogFilterPresets({ logType, currentFilter, onLoad }: LogFilterPresetsProps) {
  const { t } = useTranslation('logs')
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState('')
  const [saving, setSaving] = useState(false)
  const [name, setName] = useState('')

  const { data: presets = [] } = useQuery({
    queryKey: ['log-filter-presets', logType],
    queryFn: () => fetchLogFilterPresets(logType),
  })

  const createMut = useMutation({
    mutationFn: () => createLogFilterPreset(name.trim(), logType, currentFilter),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['log-filter-presets', logType] })
      setSaving(false)
      setName('')
    },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteLogFilterPreset(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['log-filter-presets', logType] })
      setSelectedId('')
    },
  })

  const handleSelect = (id: string) => {
    setSelectedId(id)
    const p = presets.find((x) => x.id === id)
    if (p) onLoad(p.filter)
  }

  const selectClass =
    'px-3 py-1.5 text-sm border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-primary-500'
  const btnClass =
    'px-3 py-1.5 text-sm rounded-lg font-medium transition-colors disabled:opacity-50'

  return (
    <div className="flex flex-wrap items-center gap-2 mb-4 pb-4 border-b border-slate-200 dark:border-slate-700">
      <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">
        {t('presets.label')}
      </span>

      <select value={selectedId} onChange={(e) => handleSelect(e.target.value)} className={selectClass}>
        <option value="">{t('presets.select')}</option>
        {presets.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>

      {selectedId && (
        <button
          type="button"
          onClick={() => {
            if (window.confirm(t('presets.deleteConfirm'))) deleteMut.mutate(selectedId)
          }}
          className={`${btnClass} text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20`}
        >
          {t('presets.delete')}
        </button>
      )}

      {saving ? (
        <>
          <input
            type="text"
            value={name}
            maxLength={100}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            placeholder={t('presets.namePlaceholder')}
            className={selectClass}
          />
          <button
            type="button"
            disabled={!name.trim() || createMut.isPending}
            onClick={() => createMut.mutate()}
            className={`${btnClass} bg-primary-600 text-white hover:bg-primary-700`}
          >
            {t('presets.confirmSave')}
          </button>
          <button
            type="button"
            onClick={() => {
              setSaving(false)
              setName('')
            }}
            className={`${btnClass} text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700`}
          >
            {t('presets.cancel')}
          </button>
        </>
      ) : (
        <button
          type="button"
          onClick={() => setSaving(true)}
          className={`${btnClass} text-primary-600 dark:text-primary-400 hover:bg-primary-50 dark:hover:bg-primary-900/20`}
        >
          {t('presets.save')}
        </button>
      )}
    </div>
  )
}

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listDDNSRecords, deleteDDNSRecord, syncDDNSRecord } from '../../api/ddns'
import { listDNSProviders } from '../../api/dns-providers'
import { getSystemSettings, updateSystemSettings } from '../../api/settings'
import type { DDNSRecord } from '../../types/ddns'
import DDNSRecordForm from './DDNSRecordForm'
import DDNSImportFromHostsModal from './DDNSImportFromHostsModal'
import { AddButton, EmptyState, EntityCard, IconButton, PencilIcon, TrashIcon, RenewIcon } from '../common/listui'

/** Rounded status pill with a leading dot. DDNS has 3 states (ok / error / never)
 *  so this stays local rather than using the 2-state shared StatusPill. */
function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('ddns')
  const map: Record<string, { cls: string; dot: string; label: string }> = {
    ok: {
      cls: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300',
      dot: 'bg-emerald-500',
      label: t('statusOk'),
    },
    error: {
      cls: 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300',
      dot: 'bg-red-500',
      label: t('statusError'),
    },
  }
  const s = map[status] || {
    cls: 'bg-slate-100 text-slate-500 dark:bg-slate-700/50 dark:text-slate-400',
    dot: 'bg-slate-400',
    label: t('statusNever'),
  }
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${s.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  )
}

interface RecordCardProps {
  record: DDNSRecord
  providerName: string
  formatDate: (iso?: string) => string
  onSync: (id: string) => void
  onEdit: (record: DDNSRecord) => void
  onDelete: (id: string) => void
  syncing: boolean
  deleting: boolean
}

function RecordCard({ record, providerName, formatDate, onSync, onEdit, onDelete, syncing, deleting }: RecordCardProps) {
  const { t } = useTranslation('ddns')
  const isManaged = !!record.proxy_host_id

  return (
    <EntityCard active={record.last_status === 'error'}>
      <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300">
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-semibold text-slate-900 dark:text-white">{record.hostname}</span>
            {isManaged && (
              <span
                className="inline-flex items-center rounded-md bg-cyan-50 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-cyan-700 dark:bg-cyan-900/20 dark:text-cyan-300"
                title={t('managedHint')}
              >
                {t('managedBadge')}
              </span>
            )}
            {!record.enabled && (
              <span className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-500 dark:bg-slate-700/50 dark:text-slate-400">
                {t('disabledBadge')}
              </span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
            <span>{providerName}</span>
            <span className="text-slate-300 dark:text-slate-600">·</span>
            <span className="font-mono text-slate-600 dark:text-slate-300">{record.last_ip || '-'}</span>
            <span className="text-slate-300 dark:text-slate-600">·</span>
            <span title={t('lastSynced')}>{formatDate(record.last_synced_at)}</span>
          </div>
          {record.last_status === 'error' && record.last_error && (
            <p className="mt-1.5 max-w-xl break-words text-xs text-red-600 dark:text-red-400" title={record.last_error}>
              {record.last_error}
            </p>
          )}
        </div>

        <StatusBadge status={record.last_status} />

        <div className="flex items-center gap-0.5">
          <IconButton onClick={() => onSync(record.id)} disabled={syncing} title={t('syncNow')}>
            <RenewIcon />
          </IconButton>
          <IconButton
            onClick={() => onEdit(record)}
            title={isManaged ? t('managedFieldsLocked') : t('edit')}
          >
            <PencilIcon />
          </IconButton>
          <IconButton
            onClick={() => onDelete(record.id)}
            disabled={deleting || isManaged}
            title={isManaged ? t('managedHint') : t('delete')}
            variant="danger"
          >
            <TrashIcon />
          </IconButton>
        </div>
      </div>
    </EntityCard>
  )
}

export default function DDNSRecordList() {
  const { t } = useTranslation('ddns')
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [editingRecord, setEditingRecord] = useState<DDNSRecord | null>(null)
  const [page, setPage] = useState(1)

  const { data, isLoading, error } = useQuery({
    queryKey: ['ddns-records', page],
    queryFn: () => listDDNSRecords(page),
  })

  const { data: providersData } = useQuery({
    queryKey: ['dns-providers'],
    queryFn: () => listDNSProviders(),
  })

  const providerName = (id: string): string => {
    const p = providersData?.data?.find((x) => x.id === id)
    return p ? p.name : id
  }

  // DDNS check interval (system setting) — renewal cadence in minutes.
  const { data: systemSettings } = useQuery({
    queryKey: ['system-settings'],
    queryFn: getSystemSettings,
  })
  const [intervalInput, setIntervalInput] = useState('')
  const [intervalSaved, setIntervalSaved] = useState(false)

  useEffect(() => {
    if (systemSettings?.ddns_check_interval_minutes != null) {
      setIntervalInput(String(systemSettings.ddns_check_interval_minutes))
    }
  }, [systemSettings?.ddns_check_interval_minutes])

  const intervalMutation = useMutation({
    mutationFn: (minutes: number) => updateSystemSettings({ ddns_check_interval_minutes: minutes }),
    onSuccess: () => {
      setIntervalSaved(true)
      setTimeout(() => setIntervalSaved(false), 2000)
      queryClient.invalidateQueries({ queryKey: ['system-settings'] })
    },
  })

  const handleSaveInterval = () => {
    const minutes = Math.max(1, parseInt(intervalInput, 10) || 1)
    setIntervalInput(String(minutes))
    intervalMutation.mutate(minutes)
  }

  const deleteMutation = useMutation({
    mutationFn: deleteDDNSRecord,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ddns-records'] })
    },
  })

  const syncMutation = useMutation({
    mutationFn: syncDDNSRecord,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ddns-records'] })
    },
    onError: () => {
      // Status is reflected on the record itself (last_status/last_error); refresh.
      queryClient.invalidateQueries({ queryKey: ['ddns-records'] })
    },
  })

  const handleDelete = (id: string) => {
    if (confirm(t('confirmDelete'))) {
      deleteMutation.mutate(id)
    }
  }

  const handleEdit = (record: DDNSRecord) => {
    setEditingRecord(record)
    setShowForm(true)
  }

  const handleFormClose = () => {
    setShowForm(false)
    setEditingRecord(null)
  }

  const formatDate = (iso?: string): string => {
    if (!iso) return '-'
    const d = new Date(iso)
    if (isNaN(d.getTime())) return '-'
    return d.toLocaleString()
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded">
        {t('loadError')}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('title')}</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowImport(true)}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-slate-900"
          >
            {t('importFromHosts')}
          </button>
          <AddButton onClick={() => setShowForm(true)}>{t('addRecord')}</AddButton>
        </div>
      </div>

      {/* DDNS check interval setting */}
      <div className="bg-white dark:bg-slate-800 shadow rounded-lg border border-slate-200 dark:border-slate-700 p-4">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          {t('checkIntervalMinutes')}
        </label>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t('checkIntervalDesc')}</p>
        <div className="flex items-center gap-3">
          <input
            type="number"
            min={1}
            value={intervalInput}
            onChange={(e) => setIntervalInput(e.target.value)}
            className="w-32 rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white"
          />
          <button
            type="button"
            onClick={handleSaveInterval}
            disabled={intervalMutation.isPending}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg text-sm font-medium hover:bg-primary-700 disabled:opacity-50"
          >
            {t('save')}
          </button>
          {intervalSaved && (
            <span className="text-sm text-green-600 dark:text-green-400">{t('checkIntervalSaved')}</span>
          )}
        </div>
      </div>

      {showForm && (
        <DDNSRecordForm
          record={editingRecord}
          onClose={handleFormClose}
          onSuccess={() => {
            handleFormClose()
            queryClient.invalidateQueries({ queryKey: ['ddns-records'] })
          }}
        />
      )}

      {showImport && (
        <DDNSImportFromHostsModal
          onClose={() => setShowImport(false)}
          onSuccess={() => {
            setShowImport(false)
            queryClient.invalidateQueries({ queryKey: ['ddns-records'] })
            // import bulk-enables ddns on the selected proxy hosts -> refresh
            // proxy-host caches so their ddns_enabled flags aren't stale. (#157)
            queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
          }}
        />
      )}

      {!data?.data?.length ? (
        <EmptyState
          icon={
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        >
          {t('emptyState')}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {data?.data?.map((record) => (
            <RecordCard
              key={record.id}
              record={record}
              providerName={providerName(record.dns_provider_id)}
              formatDate={formatDate}
              onSync={(id) => syncMutation.mutate(id)}
              onEdit={handleEdit}
              onDelete={handleDelete}
              syncing={syncMutation.isPending}
              deleting={deleteMutation.isPending}
            />
          ))}
        </div>
      )}

      {/* Pagination (#162: list was capped at the first page of 20) */}
      {(data?.total_pages || 1) > 1 && (
        <div className="flex items-center justify-center gap-2 mt-4">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.prev', { defaultValue: '이전' })}
          </button>
          <span className="px-4 py-1.5 text-sm text-slate-600 dark:text-slate-400">
            {page} / {data?.total_pages || 1}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(data?.total_pages || 1, p + 1))}
            disabled={page === (data?.total_pages || 1)}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.next', { defaultValue: '다음' })}
          </button>
        </div>
      )}
    </div>
  )
}

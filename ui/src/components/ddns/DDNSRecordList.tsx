import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { listDDNSRecords, deleteDDNSRecord, syncDDNSRecord } from '../../api/ddns'
import { listDNSProviders } from '../../api/dns-providers'
import type { DDNSRecord } from '../../types/ddns'
import DDNSRecordForm from './DDNSRecordForm'

function StatusBadge({ status }: { status: string }) {
  const { t } = useTranslation('ddns')
  if (status === 'ok') {
    return (
      <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300">
        {t('statusOk')}
      </span>
    )
  }
  if (status === 'error') {
    return (
      <span className="px-2 py-1 text-xs font-medium rounded-full bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300">
        {t('statusError')}
      </span>
    )
  }
  return (
    <span className="px-2 py-1 text-xs font-medium rounded-full bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
      {t('statusNever')}
    </span>
  )
}

export default function DDNSRecordList() {
  const { t } = useTranslation('ddns')
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingRecord, setEditingRecord] = useState<DDNSRecord | null>(null)

  const { data, isLoading, error } = useQuery({
    queryKey: ['ddns-records'],
    queryFn: () => listDDNSRecords(),
  })

  const { data: providersData } = useQuery({
    queryKey: ['dns-providers'],
    queryFn: () => listDNSProviders(),
  })

  const providerName = (id: string): string => {
    const p = providersData?.data?.find((x) => x.id === id)
    return p ? p.name : id
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
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
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
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          + {t('addRecord')}
        </button>
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

      <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('hostname')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('provider')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('lastIp')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('lastSynced')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('status')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {t('emptyState')}
                </td>
              </tr>
            ) : (
              data?.data?.map((record) => (
                <tr key={record.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">{record.hostname}</div>
                    {!record.enabled && (
                      <span className="text-xs text-slate-400">({t('enabled')}: off)</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-slate-700 dark:text-slate-300">{providerName(record.dns_provider_id)}</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm font-mono text-slate-700 dark:text-slate-300">{record.last_ip || '-'}</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-slate-500 dark:text-slate-400">{formatDate(record.last_synced_at)}</div>
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge status={record.last_status} />
                    {record.last_status === 'error' && record.last_error && (
                      <p className="mt-1 text-xs text-red-600 dark:text-red-400 max-w-xs break-words" title={record.last_error}>
                        {record.last_error}
                      </p>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right space-x-2 whitespace-nowrap">
                    <button
                      onClick={() => syncMutation.mutate(record.id)}
                      disabled={syncMutation.isPending}
                      className="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300 text-sm font-medium disabled:opacity-50"
                    >
                      {t('syncNow')}
                    </button>
                    <button
                      onClick={() => handleEdit(record)}
                      className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium"
                    >
                      {t('edit')}
                    </button>
                    <button
                      onClick={() => handleDelete(record.id)}
                      disabled={deleteMutation.isPending}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium disabled:opacity-50"
                    >
                      {t('delete')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

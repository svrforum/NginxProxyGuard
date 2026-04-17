import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { fetchProxyHosts, deleteProxyHost, testProxyHost, updateProxyHost, testProxyHostConfig, cloneProxyHost, toggleProxyHostFavorite } from '../api/proxy-hosts'
import { getCertificate } from '../api/certificates'
import type { ProxyHost } from '../types/proxy-host'
import type { ProxyHostTestResult } from '../types/proxy-host'
import { TestResultModal } from './proxy-host-list/TestResultModal'
import { CloneModal } from './proxy-host-list/CloneModal'
import { ProxyHostTable } from './proxy-host-list/ProxyHostTable'
import { ProxyHostFilters, type SortBy, type SortOrder } from './proxy-host-list/ProxyHostFilters'
import { ProxyHostBulkActions } from './proxy-host-list/ProxyHostBulkActions'
import { ToggleConfirmDialog } from './proxy-host-list/ProxyHostRow'

interface ProxyHostListProps {
  onEdit: (host: ProxyHost, tab?: 'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection') => void
  onAdd: () => void
}

interface HealthStatus {
  [hostId: string]: 'checking' | 'online' | 'offline' | 'unknown'
}

export function ProxyHostList({ onEdit, onAdd }: ProxyHostListProps) {
  const { t } = useTranslation('proxyHost')
  const queryClient = useQueryClient()
  const [healthStatus, setHealthStatus] = useState<HealthStatus>({})
  const [testingHost, setTestingHost] = useState<ProxyHost | null>(null)
  const [testResult, setTestResult] = useState<ProxyHostTestResult | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [isTestLoading, setIsTestLoading] = useState(false)
  const [toggleConfirmHost, setToggleConfirmHost] = useState<ProxyHost | null>(null)
  const [cloningHost, setCloningHost] = useState<ProxyHost | null>(null)
  // Certificate issuance progress state for clone
  const [cloneCertCreating, setCloneCertCreating] = useState(false)
  const [cloneCertProgress, setCloneCertProgress] = useState<string | null>(null)
  const [cloneCertElapsedTime, setCloneCertElapsedTime] = useState(0)
  const [cloneCertError, setCloneCertError] = useState<string | null>(null)
  const [cloneCertSuccess, setCloneCertSuccess] = useState(false)
  const [searchInput, setSearchInput] = useState('')  // For controlled input
  const [searchQuery, setSearchQuery] = useState('')  // For actual query (debounced)
  const [currentPage, setCurrentPage] = useState(1)

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== searchQuery) {
        setSearchQuery(searchInput)
        setCurrentPage(1)
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [searchInput, searchQuery])
  const [perPage, setPerPage] = useState<number>(() => {
    const saved = localStorage.getItem('proxyHostPerPage')
    return saved ? parseInt(saved, 10) : 20
  })
  const [sortBy, setSortBy] = useState<SortBy>(() => {
    const saved = localStorage.getItem('proxyHostSortBy')
    return (saved as SortBy) || 'name'
  })
  const [sortOrder, setSortOrder] = useState<SortOrder>(() => {
    const saved = localStorage.getItem('proxyHostSortOrder')
    return (saved as SortOrder) || 'asc'
  })

  const { data, isLoading, error } = useQuery({
    queryKey: ['proxy-hosts', currentPage, perPage, searchQuery, sortBy, sortOrder],
    queryFn: () => fetchProxyHosts(currentPage, perPage, searchQuery, sortBy, sortOrder),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteProxyHost,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateProxyHost(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
    },
  })

  const favoriteMutation = useMutation({
    mutationFn: toggleProxyHostFavorite,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
    },
  })

  const cloneMutation = useMutation({
    mutationFn: ({ id, domainNames, certificateId, certProvider, dnsProviderId, forwardScheme, forwardHost, forwardPort, isCreatingCert }: {
      id: string
      domainNames: string[]
      certificateId?: string
      certProvider?: string
      dnsProviderId?: string
      forwardScheme: string
      forwardHost: string
      forwardPort: number
      isCreatingCert: boolean
    }) =>
      cloneProxyHost(id, {
        domain_names: domainNames,
        certificate_id: certificateId,
        cert_provider: certProvider,
        dns_provider_id: dnsProviderId,
        forward_scheme: forwardScheme,
        forward_host: forwardHost,
        forward_port: forwardPort,
      }).then(result => ({ ...result, isCreatingCert })),
    onSuccess: async (data) => {
      queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
      queryClient.invalidateQueries({ queryKey: ['certificates'] })

      // If creating new certificate, wait for it to complete
      if (data.isCreatingCert) {
        setCloneCertCreating(true)
        setCloneCertProgress(t('actions.cloneCertIssuing'))
        setCloneCertElapsedTime(0)
        setCloneCertError(null)

        const success = await waitForCloneCertificate(data.id)

        setCloneCertCreating(false)
        if (success) {
          setCloneCertSuccess(true)
          queryClient.invalidateQueries({ queryKey: ['proxy-hosts'] })
          queryClient.invalidateQueries({ queryKey: ['certificates'] })
          // Auto-close modal after 1.5 seconds on success
          setTimeout(() => resetCloneState(), 1500)
        }
        // On error, keep modal open to show error message
      } else {
        resetCloneState()
      }
    },
  })

  const handleToggle = (host: ProxyHost) => {
    setToggleConfirmHost(host)
  }

  const confirmToggle = () => {
    if (toggleConfirmHost) {
      toggleMutation.mutate({ id: toggleConfirmHost.id, enabled: !toggleConfirmHost.enabled })
      setToggleConfirmHost(null)
    }
  }

  // Check health status for all hosts on load
  useEffect(() => {
    const hosts = data?.data || []
    hosts.forEach((host) => {
      if (!healthStatus[host.id]) {
        checkHealth(host.id)
      }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.data])

  const checkHealth = async (hostId: string) => {
    setHealthStatus((prev) => ({ ...prev, [hostId]: 'checking' }))
    try {
      const result = await testProxyHost(hostId)
      setHealthStatus((prev) => ({
        ...prev,
        [hostId]: result.status === 'ok' ? 'online' : 'offline',
      }))
    } catch {
      setHealthStatus((prev) => ({ ...prev, [hostId]: 'offline' }))
    }
  }

  const handleDelete = async (id: string) => {
    if (confirm(t('actions.deleteConfirm'))) {
      deleteMutation.mutate(id)
    }
  }

  // Certificate polling function for clone modal
  const waitForCloneCertificate = async (hostId: string, maxWaitTime = 120000): Promise<boolean> => {
    const startTime = Date.now()
    const pollInterval = 2000

    while (Date.now() - startTime < maxWaitTime) {
      const elapsed = Math.floor((Date.now() - startTime) / 1000)
      setCloneCertElapsedTime(elapsed)

      try {
        // Get the host to find its certificate
        const hosts = await fetchProxyHosts(1, 100, '', 'name', 'asc')
        const host = hosts.data.find(h => h.id === hostId)

        if (!host?.certificate_id) {
          setCloneCertProgress(`${t('actions.cloneCertIssuing')} (${elapsed}s)`)
          await new Promise(resolve => setTimeout(resolve, pollInterval))
          continue
        }

        const cert = await getCertificate(host.certificate_id)

        if (!cert) {
          setCloneCertProgress(`${t('actions.cloneCertIssuing')} (${elapsed}s)`)
          await new Promise(resolve => setTimeout(resolve, pollInterval))
          continue
        }

        if (cert.status === 'issued') {
          return true
        } else if (cert.status === 'error') {
          setCloneCertError(cert.error_message || t('actions.cloneCertFailed'))
          return false
        }

        setCloneCertProgress(`${t('actions.cloneCertIssuing')} (${elapsed}s)`)
      } catch (err) {
        console.error('Error checking certificate:', err)
        setCloneCertProgress(`${t('actions.cloneCertIssuing')} (${elapsed}s)`)
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval))
    }

    setCloneCertError('Certificate issuance timed out')
    return false
  }

  // Reset all clone-related state
  const resetCloneState = () => {
    setCloningHost(null)
    setCloneCertCreating(false)
    setCloneCertProgress(null)
    setCloneCertElapsedTime(0)
    setCloneCertError(null)
    setCloneCertSuccess(false)
  }

  const handleClone = (host: ProxyHost) => {
    setCloningHost(host)
  }

  const handleTestConfig = async (host: ProxyHost) => {
    setTestingHost(host)
    setTestResult(null)
    setTestError(null)
    setIsTestLoading(true)

    try {
      const result = await testProxyHostConfig(host.id)
      setTestResult(result)
    } catch (err) {
      setTestError((err as Error).message)
    } finally {
      setIsTestLoading(false)
    }
  }

  const handleRetest = async () => {
    if (!testingHost) return
    handleTestConfig(testingHost)
  }

  // Hosts are now sorted server-side
  const hosts = data?.data || []

  // Handle search input change (debounced via useEffect)
  const handleSearchChange = (value: string) => {
    setSearchInput(value)
  }

  // Clear search
  const handleClearSearch = () => {
    setSearchInput('')
    setSearchQuery('')
    setCurrentPage(1)
  }

  // Handle sort change
  const handleSortChange = (by: SortBy, order: SortOrder) => {
    setSortBy(by)
    setSortOrder(order)
    setCurrentPage(1)
    localStorage.setItem('proxyHostSortBy', by)
    localStorage.setItem('proxyHostSortOrder', order)
  }

  // Handle per page change
  const handlePerPageChange = (value: number) => {
    setPerPage(value)
    setCurrentPage(1)
    localStorage.setItem('proxyHostPerPage', value.toString())
  }

  // Pagination helpers
  const totalPages = data?.total_pages || 1
  const total = data?.total || 0

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-red-700 dark:text-red-400">
        Error loading proxy hosts: {(error as Error).message}
      </div>
    )
  }

  return (
    <div>
      <ProxyHostFilters
        searchInput={searchInput}
        onSearchChange={handleSearchChange}
        onClearSearch={handleClearSearch}
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSortChange={handleSortChange}
        onAdd={onAdd}
      />

      {hosts.length === 0 ? (
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-8 text-center border border-dashed border-slate-200 dark:border-slate-700">
          <div className="w-12 h-12 bg-slate-200 dark:bg-slate-700 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {searchInput ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              )}
            </svg>
          </div>
          <h3 className="text-slate-600 dark:text-slate-300 font-medium mb-1">
            {searchInput ? t('list.noResults') : t('list.empty')}
          </h3>
          <p className="text-slate-400 text-sm">
            {searchInput ? t('list.noResultsDescription', { query: searchInput }) : t('list.emptyDescription')}
          </p>
          {searchInput && (
            <button
              onClick={handleClearSearch}
              className="mt-3 text-sm text-primary-600 hover:text-primary-700 font-medium"
            >
              {t('list.clearSearch')}
            </button>
          )}
        </div>
      ) : (
        <ProxyHostTable
          hosts={hosts}
          healthStatus={healthStatus}
          onEdit={onEdit}
          onDelete={handleDelete}
          onToggle={handleToggle}
          onClone={handleClone}
          onTestConfig={handleTestConfig}
          onCheckHealth={checkHealth}
          onFavorite={(id) => favoriteMutation.mutate(id)}
          togglePending={toggleMutation.isPending}
        />
      )}

      <ProxyHostBulkActions
        currentPage={currentPage}
        totalPages={totalPages}
        total={total}
        perPage={perPage}
        onPageChange={setCurrentPage}
        onPerPageChange={handlePerPageChange}
      />

      {/* Test Result Modal */}
      {testingHost && (
        <TestResultModal
          host={testingHost}
          result={testResult}
          isLoading={isTestLoading}
          error={testError}
          onClose={() => {
            setTestingHost(null)
            setTestResult(null)
            setTestError(null)
          }}
          onRetest={handleRetest}
        />
      )}

      {/* Toggle Confirmation Modal */}
      {toggleConfirmHost && (
        <ToggleConfirmDialog
          host={toggleConfirmHost}
          isPending={toggleMutation.isPending}
          onConfirm={confirmToggle}
          onCancel={() => setToggleConfirmHost(null)}
        />
      )}

      {/* Clone Modal */}
      {cloningHost && (
        <CloneModal
          host={cloningHost}
          isPending={cloneMutation.isPending}
          isError={cloneMutation.isError}
          error={cloneMutation.error as Error | null}
          onClone={(params) => {
            cloneMutation.mutate({
              id: cloningHost.id,
              domainNames: params.domainNames,
              certificateId: params.certificateId,
              certProvider: params.certProvider,
              dnsProviderId: params.dnsProviderId,
              forwardScheme: params.forwardScheme,
              forwardHost: params.forwardHost,
              forwardPort: params.forwardPort,
              isCreatingCert: params.isCreatingCert,
            })
          }}
          onClose={() => resetCloneState()}
          certCreating={cloneCertCreating}
          certProgress={cloneCertProgress}
          certElapsedTime={cloneCertElapsedTime}
          certError={cloneCertError}
          certSuccess={cloneCertSuccess}
        />
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchDockerContainers, type DockerContainerInfo } from '../../api/docker'

interface DockerContainerSelectorProps {
  isOpen: boolean
  onClose: () => void
  onSelect: (host: string, port: number) => void
}

export function DockerContainerSelector({ isOpen, onClose, onSelect }: DockerContainerSelectorProps) {
  const { t } = useTranslation('proxyHost')
  const [containers, setContainers] = useState<DockerContainerInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const loadContainers = async () => {
    setLoading(true)
    setError('')
    try {
      const data = await fetchDockerContainers()
      setContainers(data)
    } catch {
      setError(t('dockerSelector.error'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (isOpen) {
      loadContainers()
    }
  }, [isOpen])

  if (!isOpen) return null

  const filtered = containers.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase()) ||
    c.image.toLowerCase().includes(search.toLowerCase())
  )

  const handleSelect = (_container: DockerContainerInfo, networkIP: string, port?: number) => {
    onSelect(networkIP, port || 80)
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              {t('dockerSelector.title')}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
              {t('dockerSelector.description')}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadContainers}
              disabled={loading}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              title={t('dockerSelector.refresh')}
            >
              <svg className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-2 text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Search */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-700">
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={t('dockerSelector.search')}
            className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
          />
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading && (
            <div className="flex items-center justify-center py-12 text-slate-500 dark:text-slate-400">
              <svg className="w-5 h-5 animate-spin mr-2" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              {t('dockerSelector.loading')}
            </div>
          )}

          {error && (
            <div className="text-center py-12 text-red-500 dark:text-red-400">
              <p>{error}</p>
              <button
                type="button"
                onClick={loadContainers}
                className="mt-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
              >
                {t('dockerSelector.refresh')}
              </button>
            </div>
          )}

          {!loading && !error && filtered.length === 0 && (
            <div className="text-center py-12">
              <svg className="w-12 h-12 mx-auto text-slate-300 dark:text-slate-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
              </svg>
              <p className="text-slate-500 dark:text-slate-400 font-medium">{t('dockerSelector.empty')}</p>
              <p className="text-sm text-slate-400 dark:text-slate-500 mt-1">{t('dockerSelector.emptyDescription')}</p>
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="space-y-3">
              {filtered.map(container => (
                <ContainerCard
                  key={container.name}
                  container={container}
                  onSelect={handleSelect}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ContainerCard({
  container,
  onSelect,
}: {
  container: DockerContainerInfo
  onSelect: (container: DockerContainerInfo, ip: string, port?: number) => void
}) {
  const { t } = useTranslation('proxyHost')

  const networks = container.networks || []
  const ports = container.ports || []

  // Truncate image name for display
  const shortImage = container.image.includes('/')
    ? container.image.split('/').slice(-1)[0]
    : container.image
  const displayImage = shortImage.length > 40 ? shortImage.substring(0, 37) + '...' : shortImage

  return (
    <div className="border border-slate-200 dark:border-slate-700 rounded-lg p-3 hover:border-primary-300 dark:hover:border-primary-600 transition-colors">
      {/* Container name + image */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0" />
          <span className="font-medium text-sm text-slate-900 dark:text-white truncate">{container.name}</span>
        </div>
        <span className="text-xs text-slate-500 dark:text-slate-400 ml-2 flex-shrink-0" title={container.image}>
          {displayImage}
        </span>
      </div>

      {/* Networks with select buttons */}
      <div className="space-y-2">
        {networks.map(net => (
          <div key={net.name} className="bg-slate-50 dark:bg-slate-700/50 rounded-lg px-3 py-2.5">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2 text-xs">
                <span className="px-1.5 py-0.5 bg-slate-200 dark:bg-slate-600 text-slate-600 dark:text-slate-300 rounded font-medium">{net.name}</span>
                <code className="font-mono font-semibold text-slate-800 dark:text-slate-200">{net.ip_address}</code>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {ports.length > 0 ? (
                ports.filter(p => p.protocol === 'tcp').map(p => (
                  <button
                    key={p.container_port}
                    type="button"
                    onClick={() => onSelect(container, net.ip_address, p.container_port)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-primary-600 text-white rounded-lg hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600 transition-colors shadow-sm"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                    {net.ip_address}:{p.container_port}
                  </button>
                ))
              ) : (
                <button
                  type="button"
                  onClick={() => onSelect(container, net.ip_address)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-primary-600 text-white rounded-lg hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600 transition-colors shadow-sm"
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                  {t('dockerSelector.select')} ({net.ip_address})
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

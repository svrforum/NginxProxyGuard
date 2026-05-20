import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { fetchBannedIPs, unbanIPsBulk } from '../../api/banned-ips'

interface UseUnbanAllOptions {
  activeTab: 'global' | 'hosts' | 'history'
  hostFilter: string
  typeFilter: string
  total: number
  getReasonCategory: (reason?: string) => string
  onAfter?: () => void
}

// useUnbanAll iterates the filtered banned-IP result set across pages and
// unbans in 100-ID batches (the server's per-request limit). The `total`
// snapshot bounds the loop so concurrent ban inserts can't cause runaway.
export function useUnbanAll({ activeTab, hostFilter, typeFilter, total, getReasonCategory, onAfter }: UseUnbanAllOptions) {
  const queryClient = useQueryClient()
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null)

  const run = async (): Promise<void> => {
    if (progress) return
    if (total === 0) return

    setProgress({ done: 0, total })
    try {
      const filter = activeTab === 'global' ? 'global' : activeTab === 'hosts' ? 'host' : undefined
      const proxyHostId = activeTab === 'hosts' && hostFilter !== 'all' ? hostFilter : undefined
      const perPage = 100
      let done = 0
      // Re-fetch page=1 each loop because deleting drops the page below.
      while (done < total) {
        const res = await fetchBannedIPs(1, perPage, proxyHostId, filter)
        let pageIds = (res.data || []).map(b => b.id)
        if (typeFilter !== 'all') {
          pageIds = (res.data || [])
            .filter(b => {
              const category = getReasonCategory(b.reason)
              if (typeFilter === 'auto') return b.is_auto_banned
              if (typeFilter === 'manual') return !b.is_auto_banned
              return category === typeFilter
            })
            .map(b => b.id)
        }
        if (pageIds.length === 0) break
        await unbanIPsBulk(pageIds)
        done += pageIds.length
        setProgress({ done, total })
      }
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] })
      onAfter?.()
    } finally {
      setProgress(null)
    }
  }

  return { progress, run }
}

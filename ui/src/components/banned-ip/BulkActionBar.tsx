import { useTranslation } from 'react-i18next'

interface BulkActionBarProps {
  selectedCount: number
  isPending: boolean
  onClear: () => void
  onUnban: () => void
}

export function BulkActionBar({ selectedCount, isPending, onClear, onUnban }: BulkActionBarProps) {
  const { t } = useTranslation('waf')

  if (selectedCount === 0) return null

  return (
    <div className="flex items-center justify-between bg-primary-50 dark:bg-primary-900/30 border border-primary-200 dark:border-primary-800 rounded-lg px-4 py-3">
      <span className="text-sm text-primary-700 dark:text-primary-300 font-medium">
        {t('bannedIp.bulk.selected', { count: selectedCount, defaultValue: '{{count}}개 선택됨' })}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onClear}
          className="px-3 py-1.5 text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded transition-colors"
        >
          {t('bannedIp.bulk.clear', { defaultValue: '선택 해제' })}
        </button>
        <button
          type="button"
          onClick={onUnban}
          disabled={isPending}
          className="px-3 py-1.5 text-sm bg-red-600 text-white rounded hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isPending
            ? t('bannedIp.bulk.unbanning', { defaultValue: '해제 중...' })
            : t('bannedIp.bulk.unban', { defaultValue: '선택 차단 해제' })}
        </button>
      </div>
    </div>
  )
}

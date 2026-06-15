import { useTranslation } from 'react-i18next'
import { HelpTip } from '../common/HelpTip'
import { ModalShell } from '../common/ModalShell'

interface NewBan {
  ip_address: string
  reason: string
  ban_time: number
  proxy_host_id: string
}

interface ProxyHost {
  id: string
  domain_names: string[]
}

interface AddBanModalProps {
  newBan: NewBan
  proxyHosts: ProxyHost[]
  isError: boolean
  isPending: boolean
  onChange: (next: NewBan) => void
  onClose: () => void
  onSubmit: (e: React.FormEvent) => void
}

export function AddBanModal({ newBan, proxyHosts, isError, isPending, onChange, onClose, onSubmit }: AddBanModalProps) {
  const { t } = useTranslation(['waf', 'common'])

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-md">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{t('bannedIp.modal.title')}</h3>
          <button
            onClick={onClose}
            aria-label={t('common:buttons.close')}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 rounded-lg"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={onSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
              {t('bannedIp.modal.ipLabel')}
              <HelpTip contentKey="help.bannedIp.ip" ns="waf" />
            </label>
            <input
              type="text"
              value={newBan.ip_address}
              onChange={(e) => onChange({ ...newBan, ip_address: e.target.value })}
              placeholder={t('bannedIp.modal.ipPlaceholder')}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('bannedIp.modal.hostLabel', { defaultValue: '적용 호스트' })}
            </label>
            <select
              value={newBan.proxy_host_id}
              onChange={(e) => onChange({ ...newBan, proxy_host_id: e.target.value })}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value="">{t('bannedIp.modal.globalBan', { defaultValue: '전역 차단 (모든 호스트)' })}</option>
              {proxyHosts.map(host => (
                <option key={host.id} value={host.id}>{host.domain_names[0]}</option>
              ))}
            </select>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {t('bannedIp.modal.hostHint', { defaultValue: '전역 차단은 모든 프록시 호스트에 적용됩니다.' })}
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
              {t('bannedIp.modal.reasonLabel')}
              <HelpTip contentKey="help.bannedIp.reason" ns="waf" />
            </label>
            <input
              type="text"
              value={newBan.reason}
              onChange={(e) => onChange({ ...newBan, reason: e.target.value })}
              placeholder={t('bannedIp.modal.reasonPlaceholder')}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
              {t('bannedIp.modal.durationLabel')}
              <HelpTip contentKey="help.bannedIp.duration" ns="waf" />
            </label>
            <select
              value={newBan.ban_time}
              onChange={(e) => onChange({ ...newBan, ban_time: parseInt(e.target.value) })}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
            >
              <option value={300}>{t('bannedIp.modal.durations.5m')}</option>
              <option value={600}>{t('bannedIp.modal.durations.10m')}</option>
              <option value={1800}>{t('bannedIp.modal.durations.30m')}</option>
              <option value={3600}>{t('bannedIp.modal.durations.1h')}</option>
              <option value={86400}>{t('bannedIp.modal.durations.24h')}</option>
              <option value={604800}>{t('bannedIp.modal.durations.7d')}</option>
              <option value={2592000}>{t('bannedIp.modal.durations.30d')}</option>
              <option value={0}>{t('bannedIp.modal.durations.permanent')}</option>
            </select>
          </div>
          {isError && (
            <div className="p-3 bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
              {t('bannedIp.messages.saveFailed', { defaultValue: '차단에 실패했습니다.' })}
            </div>
          )}
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg"
            >
              {t('bannedIp.actions.cancel')}
            </button>
            <button
              type="submit"
              disabled={isPending}
              className="px-4 py-2 text-sm font-medium bg-red-600 text-white rounded-lg shadow-sm hover:bg-red-700 disabled:bg-red-400"
            >
              {isPending ? t('bannedIp.actions.processing') : t('bannedIp.actions.ban')}
            </button>
          </div>
        </form>
    </ModalShell>
  )
}

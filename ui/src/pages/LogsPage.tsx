import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { LogViewer } from '../components/LogViewer'
import { SystemLogViewer } from '../components/SystemLogViewer'
import AuditLog from '../components/AuditLog'
import BotFilterLogs from '../components/BotFilterLogs'
import ExploitBlockLogs from '../components/ExploitBlockLogs'
import RawLogFiles from '../components/RawLogFiles'

export default function LogsPage({ subTab }: { subTab: 'access' | 'waf-events' | 'bot-filter' | 'exploit-blocks' | 'system' | 'audit' | 'raw-files' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for logs */}
      <div className="border-b border-slate-200 overflow-x-auto scrollbar-hide">
        <div className="flex gap-2 lg:gap-4 min-w-max">
          <button
            onClick={() => navigate('/logs/access')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'access'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.access')}
          </button>
          <button
            onClick={() => navigate('/logs/waf-events')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'waf-events'
              ? 'border-orange-600 text-orange-600 dark:text-orange-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.wafEvents')}
          </button>
          <button
            onClick={() => navigate('/logs/bot-filter')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'bot-filter'
              ? 'border-purple-600 text-purple-600 dark:text-purple-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.botFilter')}
          </button>
          <button
            onClick={() => navigate('/logs/exploit-blocks')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'exploit-blocks'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.exploitBlocks')}
          </button>
          <button
            onClick={() => navigate('/logs/system')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'system'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.system')}
          </button>
          <button
            onClick={() => navigate('/logs/audit')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'audit'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.audit')}
          </button>
          <button
            onClick={() => navigate('/logs/raw-files')}
            className={`pb-2 px-1 text-xs lg:text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'raw-files'
              ? 'border-amber-600 text-amber-600 dark:text-amber-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.logs.rawFiles')}
          </button>
        </div>
      </div>

      {subTab === 'system' ? (
        <SystemLogViewer />
      ) : subTab === 'audit' ? (
        <AuditLog />
      ) : subTab === 'raw-files' ? (
        <RawLogFiles />
      ) : subTab === 'bot-filter' ? (
        <BotFilterLogs />
      ) : subTab === 'exploit-blocks' ? (
        <ExploitBlockLogs />
      ) : (
        <LogViewer logType={subTab === 'waf-events' ? 'modsec' : subTab} />
      )}
    </div>
  )
}

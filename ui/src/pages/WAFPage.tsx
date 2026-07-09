import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { WAFSettings } from '../components/WAFSettings'
import { ExploitBlockRules } from '../components/ExploitBlockRules'
import { Fail2banManagement } from '../components/Fail2banManagement'
import { BannedIPList } from '../components/BannedIPList'
import { URIBlockManager } from '../components/URIBlockManager'
import { GlobalGeoManager } from '../components/GlobalGeoManager'
import { GlobalBotFilterManager } from '../components/GlobalBotFilterManager'
import { GlobalSecurityHeadersManager } from '../components/GlobalSecurityHeadersManager'
import { GlobalCloudProviderManager } from '../components/GlobalCloudProviderManager'
import { WAFTester } from '../components/WAFTester'

export default function WAFPage({ subTab }: { subTab: 'settings' | 'tester' | 'banned-ips' | 'uri-blocks' | 'global-geo' | 'global-bot-filter' | 'global-security-headers' | 'global-cloud' | 'exploit-rules' | 'fail2ban' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for WAF */}
      <div className="border-b border-slate-200">
        <div className="flex gap-4">
          <button
            onClick={() => navigate('/waf/settings')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'settings'
              ? 'border-orange-600 text-orange-600 dark:text-orange-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.ruleSettings')}
          </button>
          <button
            onClick={() => navigate('/waf/banned-ips')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'banned-ips'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.bannedIps')}
          </button>
          <button
            onClick={() => navigate('/waf/uri-blocks')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'uri-blocks'
              ? 'border-rose-600 text-rose-600 dark:text-rose-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.uriBlocks')}
          </button>
          <button
            onClick={() => navigate('/waf/global-geo')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'global-geo'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.globalGeo')}
          </button>
          <button
            onClick={() => navigate('/waf/global-bot-filter')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'global-bot-filter'
              ? 'border-orange-600 text-orange-600 dark:text-orange-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.globalBotFilter')}
          </button>
          <button
            onClick={() => navigate('/waf/global-security-headers')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'global-security-headers'
              ? 'border-blue-600 text-blue-600 dark:text-blue-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.globalSecurityHeaders')}
          </button>
          <button
            onClick={() => navigate('/waf/global-cloud')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'global-cloud'
              ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.globalCloud')}
          </button>
          <button
            onClick={() => navigate('/waf/exploit-rules')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'exploit-rules'
              ? 'border-amber-600 text-amber-600 dark:text-amber-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.exploitRules')}
          </button>
          <button
            onClick={() => navigate('/waf/fail2ban')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'fail2ban'
              ? 'border-red-600 text-red-600 dark:text-red-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.fail2ban')}
          </button>
          <button
            onClick={() => navigate('/waf/tester')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'tester'
              ? 'border-purple-600 text-purple-600 dark:text-purple-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.waf.tester')}
          </button>
        </div>
      </div>

      {subTab === 'settings' && <WAFSettings />}
      {subTab === 'banned-ips' && <BannedIPList />}
      {subTab === 'uri-blocks' && <URIBlockManager />}
      {subTab === 'global-geo' && <GlobalGeoManager />}
      {subTab === 'global-bot-filter' && <GlobalBotFilterManager />}
      {subTab === 'global-security-headers' && <GlobalSecurityHeadersManager />}
      {subTab === 'global-cloud' && <GlobalCloudProviderManager />}
      {subTab === 'exploit-rules' && <ExploitBlockRules />}
      {subTab === 'fail2ban' && <Fail2banManagement />}
      {subTab === 'tester' && <WAFTester />}
    </div>
  )
}

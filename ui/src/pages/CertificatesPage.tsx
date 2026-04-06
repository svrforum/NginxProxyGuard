import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import CertificateList from '../components/CertificateList'
import CertificateHistoryList from '../components/CertificateHistory'
import DNSProviderList from '../components/DNSProviderList'

export default function CertificatesPage({ subTab }: { subTab: 'certificates' | 'history' | 'dns-providers' }) {
  const { t } = useTranslation('navigation')
  const navigate = useNavigate()

  return (
    <div className="space-y-6">
      {/* Sub-tabs for certificates */}
      <div className="border-b border-slate-200">
        <div className="flex gap-4">
          <button
            onClick={() => navigate('/certificates/list')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'certificates'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.certificates.list')}
          </button>
          <button
            onClick={() => navigate('/certificates/history')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'history'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.certificates.history')}
          </button>
          <button
            onClick={() => navigate('/certificates/dns-providers')}
            className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors ${subTab === 'dns-providers'
              ? 'border-primary-600 text-primary-600 dark:text-primary-400'
              : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
          >
            {t('subTabs.certificates.dnsProviders')}
          </button>
        </div>
      </div>

      {subTab === 'certificates' && <CertificateList />}
      {subTab === 'history' && <CertificateHistoryList />}
      {subTab === 'dns-providers' && <DNSProviderList />}
    </div>
  )
}

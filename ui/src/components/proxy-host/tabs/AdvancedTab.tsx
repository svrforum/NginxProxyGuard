import type { CreateProxyHostRequest } from '../../../types/proxy-host'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../common/HelpTip'

interface AdvancedTabProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
}

export function AdvancedTabContent({ formData, setFormData }: AdvancedTabProps) {
  const { t } = useTranslation('proxyHost')

  return (
    <div className="space-y-6">
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2 flex items-center gap-2">
          {t('form.advanced.config.title')}
          <HelpTip contentKey="help.advanced.customConfig" />
        </label>
        <textarea
          value={formData.advanced_config}
          onChange={(e) =>
            setFormData((prev) => ({ ...prev, advanced_config: e.target.value }))
          }
          rows={10}
          className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm font-mono focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
          placeholder={t('form.advanced.config.placeholder')}
        />
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          {t('form.advanced.config.description')}
        </p>
      </div>
    </div>
  )
}

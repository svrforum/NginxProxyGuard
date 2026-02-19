import { useState } from 'react'
import type { CreateProxyHostRequest } from '../../../types/proxy-host'
import type { FormErrors } from '../types'
import { useTranslation } from 'react-i18next'
import { HelpTip } from '../../common/HelpTip'
import { DockerContainerSelector } from '../DockerContainerSelector'

interface BasicTabFullProps {
  formData: CreateProxyHostRequest
  setFormData: React.Dispatch<React.SetStateAction<CreateProxyHostRequest>>
  portInput: string
  setPortInput: (value: string) => void
  errors: FormErrors
  setErrors: React.Dispatch<React.SetStateAction<FormErrors>>
  addDomain: () => void
  removeDomain: (index: number) => void
  updateDomain: (index: number, value: string) => void
}

export function BasicTabContent({
  formData,
  setFormData,
  portInput,
  setPortInput,
  errors,
  setErrors,
  addDomain,
  removeDomain,
  updateDomain,
}: BasicTabFullProps) {
  const { t } = useTranslation('proxyHost')
  const [dockerSelectorOpen, setDockerSelectorOpen] = useState(false)

  const handleDockerSelect = (host: string, port: number) => {
    setFormData(prev => ({ ...prev, forward_host: host }))
    setPortInput(port.toString())
  }

  return (
    <div className="space-y-6">
      {/* Domain Names */}
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
          {t('form.basic.domainNames')}
          <HelpTip contentKey="help.domainNames" />
        </label>
        <div className="space-y-2">
          {formData.domain_names.map((domain, index) => (
            <div key={index} className="flex gap-2">
              <input
                type="text"
                value={domain}
                onChange={(e) => updateDomain(index, e.target.value)}
                placeholder={t('form.basic.domainPlaceholder')}
                className="flex-1 rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
              />
              {formData.domain_names.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeDomain(index)}
                  className="p-2 text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg"
                >
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              )}
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addDomain}
          className="mt-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 flex items-center gap-1"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          {t('form.basic.addDomain')}
        </button>
        {errors.domain_names && (
          <p className="mt-2 text-sm text-red-600 dark:text-red-400">{errors.domain_names}</p>
        )}
      </div>

      {/* Forward Configuration */}
      <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-4 transition-colors">
        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
          {t('form.basic.forwardHost')}
          <HelpTip contentKey="help.forwardHost" />
        </label>

        {/* Visual representation */}
        <div className="mb-4 p-3 bg-white dark:bg-slate-700 rounded-lg border border-slate-200 dark:border-slate-600">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-slate-500 dark:text-slate-400">→</span>
            <code className="px-2 py-1 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded font-medium">
              {formData.domain_names[0] || 'your-domain.com'}
            </code>
            <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
            <code className="px-2 py-1 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded font-medium">
              {formData.forward_scheme}://{formData.forward_host || 'host'}:{portInput || '??'}
            </code>
          </div>
        </div>

        <div className="grid grid-cols-12 gap-3">
          {/* Scheme */}
          <div className="col-span-3">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-1">
              {t('form.basic.forwardScheme')}
              <HelpTip contentKey="help.forwardScheme" />
            </label>
            <select
              value={formData.forward_scheme}
              onChange={(e) =>
                setFormData((prev) => ({
                  ...prev,
                  forward_scheme: e.target.value as 'http' | 'https',
                }))
              }
              className="w-full rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white font-medium"
            >
              <option value="http">http://</option>
              <option value="https">https://</option>
            </select>
          </div>

          {/* Host */}
          <div className="col-span-6">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-1">
              {t('form.basic.forwardHost')}
              <HelpTip contentKey="help.forwardHost" />
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={formData.forward_host}
                onChange={(e) =>
                  setFormData((prev) => ({ ...prev, forward_host: e.target.value }))
                }
                placeholder={t('form.basic.forwardHostPlaceholder')}
                className={`flex-1 rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400 ${errors.forward_host ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'
                  }`}
              />
              <button
                type="button"
                onClick={() => setDockerSelectorOpen(true)}
                className="flex-shrink-0 px-3 py-2.5 text-xs font-medium bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 border border-blue-200 dark:border-blue-800 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors flex items-center gap-1.5"
                title={t('form.basic.dockerBrowse')}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                </svg>
                {t('form.basic.dockerBrowseShort')}
              </button>
            </div>
            {errors.forward_host && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{errors.forward_host}</p>
            )}
          </div>

          {/* Port */}
          <div className="col-span-3">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5 flex items-center gap-1">
              {t('form.basic.forwardPort')}
              <HelpTip contentKey="help.forwardPort" />
            </label>
            <input
              type="text"
              inputMode="numeric"
              value={portInput}
              onChange={(e) => {
                const value = e.target.value
                if (value === '' || /^\d+$/.test(value)) {
                  setPortInput(value)
                }
              }}
              onBlur={() => {
                const port = parseInt(portInput)
                if (portInput && (isNaN(port) || port < 1 || port > 65535)) {
                  setErrors(prev => ({ ...prev, forward_port: t('validation.portRange') }))
                } else {
                  setErrors(prev => {
                    const { forward_port: _forward_port, ...rest } = prev
                    return rest
                  })
                }
              }}
              placeholder="80"
              className={`w-full rounded-lg border px-3 py-2.5 text-sm focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400 text-center font-mono ${errors.forward_port ? 'border-red-300 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'
                }`}
            />
            {errors.forward_port && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{errors.forward_port}</p>
            )}
          </div>
        </div>

        {/* Common ports hint */}
        <div className="mt-3 flex gap-2">
          <span className="text-xs text-slate-500 dark:text-slate-400">{t('common:labels.port')}:</span>
          {[80, 443, 3000, 8080, 8443].map(port => (
            <button
              key={port}
              type="button"
              onClick={() => setPortInput(port.toString())}
              className={`px-2 py-0.5 text-xs rounded ${portInput === port.toString()
                ? 'bg-primary-100 text-primary-700 dark:bg-primary-900/40 dark:text-primary-300'
                : 'bg-slate-200 text-slate-600 hover:bg-slate-300 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600'
                }`}
            >
              {port}
            </button>
          ))}
        </div>
      </div>

      {/* Docker Container Selector Modal */}
      <DockerContainerSelector
        isOpen={dockerSelectorOpen}
        onClose={() => setDockerSelectorOpen(false)}
        onSelect={handleDockerSelect}
      />
    </div>
  )
}

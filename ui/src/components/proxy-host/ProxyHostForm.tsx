import type { ProxyHost } from '../../types/proxy-host'
import { useProxyHostForm } from './hooks/useProxyHostForm'
import { BasicTabContent } from './tabs/BasicTab'
import { SSLTabContent } from './tabs/SSLTab'
import { SecurityTabContent } from './tabs/SecurityTab'
import { PerformanceTabContent } from './tabs/PerformanceTab'
import { AdvancedTabContent } from './tabs/AdvancedTab'
import { ProtectionTabContent } from './tabs/ProtectionTab'
import { SaveProgressModal } from './SaveProgressModal'
import { CertificateLogModal } from '../CertificateLogModal'
import type { TabType } from './types'
import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useEscapeKey } from '../../hooks/useEscapeKey'

interface ProxyHostFormProps {
  host?: ProxyHost | null
  initialTab?: TabType
  onClose: () => void
}

export function ProxyHostForm({ host, initialTab, onClose }: ProxyHostFormProps) {
  const { t } = useTranslation('proxyHost')
  const [activeTab, setActiveTab] = useState<TabType>(initialTab || 'basic')

  const {
    // State
    formData,
    setFormData,
    portInput,
    setPortInput,
    errors,
    setErrors,
    isEditing,

    // Certificate
    certState,
    setCertMode,
    setNewCertData,

    // Bot filter
    botFilterData,
    setBotFilterData,

    // GeoIP
    geoData,
    setGeoData,
    geoSearchTerm,
    setGeoSearchTerm,
    allowedIPsInput,
    setAllowedIPsInput,

    // Cloud provider blocking
    blockedCloudProviders,
    setBlockedCloudProviders,
    cloudProviderChallengeMode,
    setCloudProviderChallengeMode,
    cloudProviderAllowSearchBots,
    setCloudProviderAllowSearchBots,

    // Data from queries
    availableCerts,
    pendingCerts,
    availableAccessLists,
    dnsProviders,
    geoipStatus,
    countryCodes,

    // Mutations
    mutation,
    certCreating,

    // Save progress
    saveProgress,
    closeSaveProgress,

    // Certificate log modal
    pendingCertId,
    closeCertLogModal,

    // Handlers
    handleSubmit,
    addDomain,
    removeDomain,
    updateDomain,
  } = useProxyHostForm(host, onClose)

  // ESC to close (but not during save progress unless there's an error)
  useEscapeKey(onClose, !saveProgress.isOpen || (saveProgress.isOpen && !!saveProgress.error))

  // Auto-switch to tab with error on validation failure
  useEffect(() => {
    if (Object.keys(errors).length > 0) {
      if (errors.domain_names || errors.forward_host || errors.forward_port) {
        setActiveTab('basic')
      } else if (errors.certificate_id) {
        setActiveTab('ssl')
      }
    }
  }, [errors])

  // Protection tab available for both new and existing hosts
  const tabs = [
    { id: 'basic' as TabType, label: t('form.tabs.basic'), icon: '🌐' },
    { id: 'ssl' as TabType, label: t('form.tabs.ssl'), icon: '🔒' },
    { id: 'security' as TabType, label: t('form.tabs.security'), icon: '🛡️' },
    { id: 'protection' as TabType, label: t('form.tabs.protection'), icon: '🚫' },
    { id: 'performance' as TabType, label: t('form.tabs.performance'), icon: '⚡' },
    { id: 'advanced' as TabType, label: t('form.tabs.advanced'), icon: '⚙️' },
  ]

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl w-full max-w-3xl min-h-[600px] max-h-[90vh] overflow-hidden flex flex-col transition-colors">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between bg-slate-50 dark:bg-slate-800/50">
          <div className="flex items-center gap-4">
            <div>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white">
                {isEditing ? t('form.editTitle') : t('form.addTitle')}
              </h2>
              {isEditing && host && (
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">{host.domain_names.join(', ')}</p>
              )}
            </div>
            {/* Enable/Disable Toggle */}
            <button
              type="button"
              onClick={() => setFormData(prev => ({ ...prev, enabled: !prev.enabled }))}
              className={`relative inline-flex h-7 w-14 items-center rounded-full transition-colors ${formData.enabled ? 'bg-green-500' : 'bg-slate-300 dark:bg-slate-600'
                }`}
              title={formData.enabled ? t('actions.disable') : t('actions.enable')}
            >
              <span
                className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-sm transition-transform ${formData.enabled ? 'translate-x-8' : 'translate-x-1'
                  }`}
              />
              <span className={`absolute text-[10px] font-bold ${formData.enabled ? 'left-1.5 text-white' : 'right-1.5 text-slate-500'}`}>
                {formData.enabled ? 'ON' : 'OFF'}
              </span>
            </button>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="px-6 border-b border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
          <nav className="flex gap-1 -mb-px">
            {tabs.map(tab => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors flex items-center gap-2 ${activeTab === tab.id
                  ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:border-slate-300 dark:hover:border-slate-600'
                  }`}
              >
                <span>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Form Content */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto">
          <div className="p-6">
            {/* Basic Tab */}
            {activeTab === 'basic' && (
              <BasicTabContent
                formData={formData}
                setFormData={setFormData}
                portInput={portInput}
                setPortInput={setPortInput}
                errors={errors}
                setErrors={setErrors}
                addDomain={addDomain}
                removeDomain={removeDomain}
                updateDomain={updateDomain}
              />
            )}

            {/* SSL Tab */}
            {activeTab === 'ssl' && (
              <SSLTabContent
                formData={formData}
                setFormData={setFormData}
                certState={certState}
                setCertMode={setCertMode}
                setNewCertData={setNewCertData}
                errors={errors}
                availableCerts={availableCerts}
                pendingCerts={pendingCerts}
                dnsProviders={dnsProviders}
              />
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <SecurityTabContent
                hostId={host?.id}
                formData={formData}
                setFormData={setFormData}
                botFilterData={botFilterData}
                setBotFilterData={setBotFilterData}
                geoData={geoData}
                setGeoData={setGeoData}
                geoSearchTerm={geoSearchTerm}
                setGeoSearchTerm={setGeoSearchTerm}
                allowedIPsInput={allowedIPsInput}
                setAllowedIPsInput={setAllowedIPsInput}
                blockedCloudProviders={blockedCloudProviders}
                setBlockedCloudProviders={setBlockedCloudProviders}
                cloudProviderChallengeMode={cloudProviderChallengeMode}
                setCloudProviderChallengeMode={setCloudProviderChallengeMode}
                cloudProviderAllowSearchBots={cloudProviderAllowSearchBots}
                setCloudProviderAllowSearchBots={setCloudProviderAllowSearchBots}
                availableAccessLists={availableAccessLists}
                geoipStatus={geoipStatus}
                countryCodes={countryCodes}
              />
            )}

            {/* Performance Tab */}
            {activeTab === 'performance' && (
              <PerformanceTabContent
                formData={formData}
                setFormData={setFormData}
              />
            )}

            {/* Advanced Tab */}
            {activeTab === 'advanced' && (
              <AdvancedTabContent
                formData={formData}
                setFormData={setFormData}
              />
            )}

            {/* Protection Tab */}
            {activeTab === 'protection' && (
              isEditing && host ? (
                <ProtectionTabContent hostId={host.id} />
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <div className="w-16 h-16 rounded-full bg-slate-100 dark:bg-slate-700 flex items-center justify-center mb-4">
                    <svg className="w-8 h-8 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">{t('form.protection.notAvailable.title')}</h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400 max-w-md">{t('form.protection.notAvailable.description')}</p>
                </div>
              )
            )}
          </div>

          {/* Error message */}
          {mutation.isError && (
            <div className="mx-6 mb-4 bg-red-50 border border-red-200 rounded-lg p-4 text-red-700 text-sm">
              {(mutation.error as Error).message}
            </div>
          )}

          {/* Footer Actions */}
          {/* Footer Actions */}
          <div className="px-6 py-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between">
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {isEditing ? t('form.editTitle') : (
                formData.ssl_enabled && certState.mode === 'create'
                  ? t('form.ssl.creatingCertificate')
                  : t('form.addTitle')
              )}
            </div>
            <div className="flex gap-3">
              <button
                type="button"
                onClick={onClose}
                disabled={certCreating || mutation.isPending}
                className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors disabled:opacity-50"
              >
                {t('common:buttons.cancel')}
              </button>

              {/* Wizard Navigation (only for Create mode) */}
              {!isEditing && (
                <>
                  {/* Previous Button */}
                  {tabs.findIndex(t => t.id === activeTab) > 0 && (
                    <button
                      type="button"
                      onClick={() => {
                        const currentIndex = tabs.findIndex(t => t.id === activeTab)
                        if (currentIndex > 0) {
                          setActiveTab(tabs[currentIndex - 1].id)
                        }
                      }}
                      disabled={certCreating || mutation.isPending}
                      className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors disabled:opacity-50"
                    >
                      {t('common:buttons.previous')}
                    </button>
                  )}

                  {/* Next Button */}
                  {tabs.findIndex(t => t.id === activeTab) < tabs.length - 1 && (
                    <button
                      type="button"
                      onClick={() => {
                        const currentIndex = tabs.findIndex(t => t.id === activeTab)
                        if (currentIndex < tabs.length - 1) {
                          setActiveTab(tabs[currentIndex + 1].id)
                        }
                      }}
                      disabled={certCreating || mutation.isPending}
                      className="bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors"
                    >
                      {t('common:buttons.next')}
                    </button>
                  )}
                </>
              )}

              {/* Save/Create Button (Always visible in Edit mode, or last tab in Create mode) */}
              {(isEditing || tabs.findIndex(t => t.id === activeTab) === tabs.length - 1) && (
                <button
                  type="submit"
                  disabled={certCreating || mutation.isPending}
                  className="bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white px-6 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                >
                  {(certCreating || mutation.isPending) && (
                    <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                  )}
                  {certCreating ? t('form.ssl.creatingCertificate') : (
                    isEditing ? t('common:buttons.save') : t('common:buttons.create')
                  )}
                </button>
              )}
            </div>
          </div>
        </form>
      </div>

      {/* Save Progress Modal */}
      <SaveProgressModal
        isOpen={saveProgress.isOpen}
        isEditing={isEditing}
        currentStep={saveProgress.currentStep}
        error={saveProgress.error}
        errorDetails={saveProgress.errorDetails}
        onClose={closeSaveProgress}
      />

      {/* Certificate Log Modal */}
      <CertificateLogModal
        isOpen={!!pendingCertId}
        certificateId={pendingCertId}
        onClose={closeCertLogModal}
      />
    </div>
  )
}

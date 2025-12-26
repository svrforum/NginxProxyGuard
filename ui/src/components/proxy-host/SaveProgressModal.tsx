import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useEscapeKey } from '../../hooks/useEscapeKey'

interface SaveProgressModalProps {
  isOpen: boolean
  isEditing: boolean
  currentStep: number
  error?: string | null
  errorDetails?: string | null
  onClose?: () => void
}

interface Step {
  key: string
  label: string
  description: string
}

export function SaveProgressModal({ isOpen, isEditing, currentStep, error, errorDetails, onClose }: SaveProgressModalProps) {
  const { t } = useTranslation(['proxyHost', 'common'])
  const [elapsedTime, setElapsedTime] = useState(0)
  const [showDetails, setShowDetails] = useState(false)

  // Allow ESC to close only when there's an error and onClose is provided
  useEscapeKey(() => onClose?.(), isOpen && !!error && !!onClose)

  // Simplified 3-step process
  const steps: Step[] = [
    {
      key: 'server',
      label: t('saveProgress.steps.server'),
      description: t('saveProgress.steps.serverDesc'),
    },
    {
      key: 'additional',
      label: t('saveProgress.steps.additional'),
      description: t('saveProgress.steps.additionalDesc'),
    },
    {
      key: 'complete',
      label: t('saveProgress.steps.complete'),
      description: t('saveProgress.steps.completeDesc'),
    },
  ]

  useEffect(() => {
    if (!isOpen) {
      setElapsedTime(0)
      return
    }

    const interval = setInterval(() => {
      setElapsedTime((prev) => prev + 0.1)
    }, 100)

    return () => clearInterval(interval)
  }, [isOpen])

  if (!isOpen) return null

  const getStepStatus = (index: number) => {
    if (error && index === currentStep) return 'error'
    if (index < currentStep) return 'completed'
    if (index === currentStep) return 'active'
    return 'pending'
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
              {isEditing ? t('saveProgress.titleUpdate') : t('saveProgress.titleCreate')}
            </h3>
            <span className="text-sm text-slate-500 dark:text-slate-400">
              {elapsedTime.toFixed(1)}s
            </span>
          </div>
        </div>

        {/* Progress Steps */}
        <div className="px-6 py-4 space-y-3">
          {steps.map((step, index) => {
            const status = getStepStatus(index)
            return (
              <div
                key={step.key}
                className={`flex items-start gap-3 p-3 rounded-lg transition-all duration-300 ${
                  status === 'active'
                    ? 'bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800'
                    : status === 'error'
                    ? 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
                    : status === 'completed'
                    ? 'bg-green-50 dark:bg-green-900/20'
                    : 'bg-slate-50 dark:bg-slate-700/30'
                }`}
              >
                {/* Status Icon */}
                <div className="flex-shrink-0 mt-0.5">
                  {status === 'completed' ? (
                    <div className="w-5 h-5 rounded-full bg-green-500 flex items-center justify-center">
                      <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                  ) : status === 'active' ? (
                    <div className="w-5 h-5 rounded-full border-2 border-primary-500 border-t-transparent animate-spin" />
                  ) : status === 'error' ? (
                    <div className="w-5 h-5 rounded-full bg-red-500 flex items-center justify-center">
                      <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </div>
                  ) : (
                    <div className="w-5 h-5 rounded-full border-2 border-slate-300 dark:border-slate-600" />
                  )}
                </div>

                {/* Step Info */}
                <div className="flex-1 min-w-0">
                  <div
                    className={`text-sm font-medium ${
                      status === 'active'
                        ? 'text-primary-700 dark:text-primary-300'
                        : status === 'error'
                        ? 'text-red-700 dark:text-red-300'
                        : status === 'completed'
                        ? 'text-green-700 dark:text-green-300'
                        : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {step.label}
                  </div>
                  {(status === 'active' || status === 'error') && (
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      {status === 'error' ? error : step.description}
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>

        {/* Error Details */}
        {error && (
          <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700">
            <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <div className="flex-shrink-0">
                  <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className="text-sm font-medium text-red-800 dark:text-red-200">
                    {error}
                  </h4>
                  {errorDetails && (
                    <div className="mt-2">
                      <button
                        type="button"
                        onClick={() => setShowDetails(!showDetails)}
                        className="text-xs text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200 flex items-center gap-1"
                      >
                        <svg
                          className={`w-3 h-3 transition-transform ${showDetails ? 'rotate-90' : ''}`}
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                        {showDetails ? t('saveProgress.hideDetails', 'Hide Details') : t('saveProgress.showDetails', 'Show Details')}
                      </button>
                      {showDetails && (
                        <pre className="mt-2 p-3 bg-slate-900 dark:bg-slate-950 rounded-md text-xs text-red-300 overflow-x-auto whitespace-pre-wrap break-words max-h-48 overflow-y-auto font-mono">
                          {errorDetails}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Error Actions */}
        {error && onClose && (
          <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
            <button
              onClick={onClose}
              className="w-full px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors"
            >
              {t('common:buttons.close')}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

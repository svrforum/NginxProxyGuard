import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import {
  getAccountInfo,
  changePassword,
  changeUsername,
  setup2FA,
  enable2FA,
  disable2FA,
  setFontFamily as setFontFamilyAPI,
  AccountInfo,
  Setup2FAResponse,
  ChangePasswordRequest,
  ChangeUsernameRequest,
  Disable2FARequest
} from '../api/auth'
import { updateSystemSettings } from '../api/settings'
import { useLanguage } from '../i18n/hooks/useLanguage'
import APITokenManager from './APITokenManager'
import { ProfileTab } from './account/ProfileTab'
import { PasswordTab } from './account/PasswordTab'
import { TwoFactorTab } from './account/TwoFactorTab'
import { LanguageFontTab } from './account/LanguageFontTab'

interface AccountSettingsProps {
  onClose: () => void
  onLogout: () => void
}

type Tab = 'info' | 'password' | '2fa' | 'api-tokens'

export default function AccountSettings({ onClose, onLogout }: AccountSettingsProps) {
  const { t } = useTranslation(['auth', 'common', 'navigation'])
  const { currentLanguage, changeLanguage, supportedLanguages, languageNames } = useLanguage(true)
  const [activeTab, setActiveTab] = useState<Tab>('info')
  const [accountInfo, setAccountInfo] = useState<AccountInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Password change state
  const [passwordForm, setPasswordForm] = useState({
    current_password: '',
    new_password: '',
    new_password_confirm: ''
  })
  const [changingPassword, setChangingPassword] = useState(false)

  // 2FA state
  const [setup2FAData, setSetup2FAData] = useState<Setup2FAResponse | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [setting2FA, setSetting2FA] = useState(false)
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [disableForm, setDisableForm] = useState<Disable2FARequest>({
    password: '',
    totp_code: ''
  })
  const [disabling2FA, setDisabling2FA] = useState(false)

  // Font family state
  const [currentFontFamily, setCurrentFontFamily] = useState('system')
  const [changingFont, setChangingFont] = useState(false)

  // Username change state
  const [usernameForm, setUsernameForm] = useState<ChangeUsernameRequest>({
    current_password: '',
    new_username: ''
  })
  const [changingUsername, setChangingUsername] = useState(false)
  const [showUsernameForm, setShowUsernameForm] = useState(false)

  useEffect(() => {
    loadAccountInfo()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loadAccountInfo = async () => {
    try {
      setLoading(true)
      const info = await getAccountInfo()
      setAccountInfo(info)
      setCurrentFontFamily(info.font_family || 'system')
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToLoadAccount'))
    } finally {
      setLoading(false)
    }
  }

  const handleFontFamilyChange = async (fontFamily: string) => {
    try {
      setChangingFont(true)
      // Update user preference
      await setFontFamilyAPI(fontFamily)
      // Update system-wide setting (for welcome/403 pages)
      await updateSystemSettings({ ui_font_family: fontFamily })
      setCurrentFontFamily(fontFamily)
      // Apply font globally
      document.documentElement.setAttribute('data-font', fontFamily)
      localStorage.setItem('npg_font_family', fontFamily)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change font')
    } finally {
      setChangingFont(false)
    }
  }

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (passwordForm.new_password !== passwordForm.new_password_confirm) {
      setError(t('account.password.mismatch'))
      return
    }

    if (passwordForm.new_password.length < 10) {
      setError(t('account.password.minLengthError'))
      return
    }

    try {
      setChangingPassword(true)
      await changePassword(passwordForm as ChangePasswordRequest)
      setSuccess(t('account.password.success'))
      setPasswordForm({ current_password: '', new_password: '', new_password_confirm: '' })
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToChangePassword'))
    } finally {
      setChangingPassword(false)
    }
  }

  const handleUsernameChange = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (usernameForm.new_username.length < 3) {
      setError(t('account.username.minLengthError'))
      return
    }

    if (usernameForm.new_username === accountInfo?.username) {
      setError(t('account.username.sameAsCurrentError'))
      return
    }

    try {
      setChangingUsername(true)
      const result = await changeUsername(usernameForm as ChangeUsernameRequest)
      setSuccess(t('account.username.success'))
      setUsernameForm({ current_password: '', new_username: '' })
      setShowUsernameForm(false)
      // Reload account info to reflect the new username
      if (accountInfo) {
        setAccountInfo({ ...accountInfo, username: result.username })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToChangeUsername'))
    } finally {
      setChangingUsername(false)
    }
  }

  const handleSetup2FA = async () => {
    setError('')
    try {
      setSetting2FA(true)
      const data = await setup2FA()
      setSetup2FAData(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToSetup2FA'))
    } finally {
      setSetting2FA(false)
    }
  }

  const handleEnable2FA = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!totpCode || totpCode.length !== 6) {
      setError(t('account.twoFactor.invalidCode'))
      return
    }

    try {
      setSetting2FA(true)
      await enable2FA({ totp_code: totpCode })
      setSuccess(t('account.twoFactor.enableSuccess'))
      setShowBackupCodes(true)
      await loadAccountInfo()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToEnable2FA'))
    } finally {
      setSetting2FA(false)
    }
  }

  const handleDisable2FA = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    try {
      setDisabling2FA(true)
      await disable2FA(disableForm as Disable2FARequest)
      setSuccess(t('account.twoFactor.disableSuccess'))
      setSetup2FAData(null)
      setTotpCode('')
      setDisableForm({ password: '', totp_code: '' })
      await loadAccountInfo()
    } catch (err) {
      setError(err instanceof Error ? err.message : t('errors.failedToDisable2FA'))
    } finally {
      setDisabling2FA(false)
    }
  }

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return t('account.info.never')
    return new Date(dateStr).toLocaleString()
  }

  if (loading) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8">
          <div className="animate-spin h-8 w-8 border-4 border-blue-500 border-t-transparent rounded-full mx-auto"></div>
          <p className="text-gray-900 dark:text-white mt-4">{t('account.loading')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className={`bg-white dark:bg-gray-800 rounded-lg w-full max-h-[90vh] overflow-hidden flex flex-col ${activeTab === 'api-tokens' ? 'max-w-5xl' : 'max-w-2xl'}`}>
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">{t('account.title')}</h2>
          <button
            onClick={onClose}
            className="text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white text-2xl"
          >
            &times;
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-200 dark:border-gray-700">
          {([
            ['info', t('account.tabs.info')],
            ['password', t('account.tabs.password')],
            ['2fa', t('account.tabs.twoFactor')],
            ['api-tokens', t('account.tabs.apiTokens')],
          ] as [Tab, string][]).map(([key, label]) => (
            <button
              key={key}
              onClick={() => { setActiveTab(key); setError(''); setSuccess(''); }}
              className={`px-6 py-3 font-medium ${
                activeTab === key
                  ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-500/20 border border-red-500 rounded text-red-400">
              {error}
            </div>
          )}
          {success && (
            <div className="mb-4 p-3 bg-green-500/20 border border-green-500 rounded text-green-400">
              {success}
            </div>
          )}

          {/* Account Info Tab */}
          {activeTab === 'info' && accountInfo && (
            <ProfileTab
              accountInfo={accountInfo}
              formatDate={formatDate}
              showUsernameForm={showUsernameForm}
              setShowUsernameForm={setShowUsernameForm}
              usernameForm={usernameForm}
              setUsernameForm={setUsernameForm}
              changingUsername={changingUsername}
              onUsernameChange={handleUsernameChange}
              onLogout={onLogout}
            >
              <LanguageFontTab
                currentLanguage={currentLanguage}
                supportedLanguages={supportedLanguages}
                languageNames={languageNames}
                changeLanguage={changeLanguage}
                currentFontFamily={currentFontFamily}
                changingFont={changingFont}
                onFontFamilyChange={handleFontFamilyChange}
              />
            </ProfileTab>
          )}

          {/* Password Tab */}
          {activeTab === 'password' && (
            <PasswordTab
              passwordForm={passwordForm}
              setPasswordForm={setPasswordForm}
              changingPassword={changingPassword}
              onSubmit={handlePasswordChange}
            />
          )}

          {/* 2FA Tab */}
          {activeTab === '2fa' && accountInfo && (
            <TwoFactorTab
              accountInfo={accountInfo}
              setup2FAData={setup2FAData}
              setSetup2FAData={setSetup2FAData}
              totpCode={totpCode}
              setTotpCode={setTotpCode}
              setting2FA={setting2FA}
              showBackupCodes={showBackupCodes}
              setShowBackupCodes={setShowBackupCodes}
              disableForm={disableForm}
              setDisableForm={setDisableForm}
              disabling2FA={disabling2FA}
              onSetup2FA={handleSetup2FA}
              onEnable2FA={handleEnable2FA}
              onDisable2FA={handleDisable2FA}
            />
          )}

          {/* API Tokens Tab */}
          {activeTab === 'api-tokens' && (
            <APITokenManager />
          )}
        </div>
      </div>
    </div>
  )
}

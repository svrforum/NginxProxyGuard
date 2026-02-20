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

// Font family options
const FONT_OPTIONS = [
  { value: 'system', label: 'System Default', labelKo: '시스템 기본' },
  { value: 'gowun-batang', label: 'Gowun Batang', labelKo: '고운 바탕' },
  { value: 'noto-sans-kr', label: 'Noto Sans KR', labelKo: 'Noto Sans KR' },
  { value: 'pretendard', label: 'Pretendard', labelKo: 'Pretendard' },
  { value: 'inter', label: 'Inter', labelKo: 'Inter' },
]

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
  const [disableForm, setDisableForm] = useState({
    password: '',
    totp_code: ''
  })
  const [disabling2FA, setDisabling2FA] = useState(false)

  // Font family state
  const [currentFontFamily, setCurrentFontFamily] = useState('system')
  const [changingFont, setChangingFont] = useState(false)

  // Username change state
  const [usernameForm, setUsernameForm] = useState({
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
          <button
            onClick={() => { setActiveTab('info'); setError(''); setSuccess(''); }}
            className={`px-6 py-3 font-medium ${
              activeTab === 'info'
                ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {t('account.tabs.info')}
          </button>
          <button
            onClick={() => { setActiveTab('password'); setError(''); setSuccess(''); }}
            className={`px-6 py-3 font-medium ${
              activeTab === 'password'
                ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {t('account.tabs.password')}
          </button>
          <button
            onClick={() => { setActiveTab('2fa'); setError(''); setSuccess(''); }}
            className={`px-6 py-3 font-medium ${
              activeTab === '2fa'
                ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {t('account.tabs.twoFactor')}
          </button>
          <button
            onClick={() => { setActiveTab('api-tokens'); setError(''); setSuccess(''); }}
            className={`px-6 py-3 font-medium ${
              activeTab === 'api-tokens'
                ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                : 'text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {t('account.tabs.apiTokens')}
          </button>
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
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.username')}</p>
                  {!showUsernameForm ? (
                    <div className="flex items-center justify-between">
                      <p className="text-gray-900 dark:text-white font-medium">{accountInfo.username}</p>
                      <button
                        onClick={() => {
                          setShowUsernameForm(true)
                          setUsernameForm({ ...usernameForm, new_username: accountInfo.username })
                        }}
                        className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-sm"
                      >
                        {t('common:buttons.edit')}
                      </button>
                    </div>
                  ) : (
                    <form onSubmit={handleUsernameChange} className="mt-2 space-y-2">
                      <input
                        type="text"
                        value={usernameForm.new_username}
                        onChange={(e) => setUsernameForm({ ...usernameForm, new_username: e.target.value })}
                        className="w-full px-3 py-1.5 bg-white dark:bg-gray-600 border border-gray-300 dark:border-gray-500 rounded text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:outline-none"
                        placeholder={t('account.username.newUsername')}
                        minLength={3}
                        required
                      />
                      <input
                        type="password"
                        value={usernameForm.current_password}
                        onChange={(e) => setUsernameForm({ ...usernameForm, current_password: e.target.value })}
                        className="w-full px-3 py-1.5 bg-white dark:bg-gray-600 border border-gray-300 dark:border-gray-500 rounded text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:outline-none"
                        placeholder={t('account.username.currentPassword')}
                        required
                      />
                      <div className="flex gap-2">
                        <button
                          type="submit"
                          disabled={changingUsername}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded disabled:opacity-50"
                        >
                          {changingUsername ? t('common:buttons.saving') : t('common:buttons.save')}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setShowUsernameForm(false)
                            setUsernameForm({ current_password: '', new_username: '' })
                          }}
                          className="px-3 py-1 bg-gray-200 dark:bg-gray-600 hover:bg-gray-300 dark:hover:bg-gray-500 text-gray-700 dark:text-white text-sm rounded"
                        >
                          {t('common:buttons.cancel')}
                        </button>
                      </div>
                    </form>
                  )}
                </div>
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.role')}</p>
                  <p className="text-gray-900 dark:text-white font-medium capitalize">{accountInfo.role}</p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.twoFactorStatus')}</p>
                  <p className={`font-medium ${accountInfo.totp_enabled ? 'text-green-600 dark:text-green-400' : 'text-yellow-600 dark:text-yellow-400'}`}>
                    {accountInfo.totp_enabled ? t('common:status.enabled') : t('common:status.disabled')}
                  </p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.lastLogin')}</p>
                  <p className="text-gray-900 dark:text-white font-medium text-sm">{formatDate(accountInfo.last_login_at)}</p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.lastLoginIP')}</p>
                  <p className="text-gray-900 dark:text-white font-medium">{accountInfo.last_login_ip || t('account.info.na')}</p>
                </div>
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('navigation:account.language')}</p>
                  <select
                    value={currentLanguage}
                    onChange={(e) => changeLanguage(e.target.value as 'ko' | 'en')}
                    className="mt-1 w-full px-3 py-1.5 bg-white dark:bg-gray-600 border border-gray-300 dark:border-gray-500 rounded text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:outline-none"
                  >
                    {supportedLanguages.map((lang) => (
                      <option key={lang} value={lang}>
                        {languageNames[lang]}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                  <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.fontFamily', '폰트')}</p>
                  <select
                    value={currentFontFamily}
                    onChange={(e) => handleFontFamilyChange(e.target.value)}
                    disabled={changingFont}
                    className="mt-1 w-full px-3 py-1.5 bg-white dark:bg-gray-600 border border-gray-300 dark:border-gray-500 rounded text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:outline-none disabled:opacity-50"
                  >
                    {FONT_OPTIONS.map((font) => (
                      <option key={font.value} value={font.value}>
                        {currentLanguage === 'ko' ? font.labelKo : font.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <button
                  onClick={onLogout}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded"
                >
                  {t('navigation:account.logout')}
                </button>
              </div>
            </div>
          )}

          {/* Password Tab */}
          {activeTab === 'password' && (
            <form onSubmit={handlePasswordChange} className="space-y-4">
              <div>
                <label className="block text-gray-500 dark:text-gray-400 text-sm mb-1">{t('account.password.currentPassword')}</label>
                <input
                  type="password"
                  value={passwordForm.current_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, current_password: e.target.value })}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded text-gray-900 dark:text-white focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-gray-500 dark:text-gray-400 text-sm mb-1">{t('account.password.newPassword')}</label>
                <input
                  type="password"
                  value={passwordForm.new_password}
                  onChange={(e) => setPasswordForm({ ...passwordForm, new_password: e.target.value })}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded text-gray-900 dark:text-white focus:border-blue-500 focus:outline-none"
                  minLength={8}
                  required
                />
                <p className="text-gray-500 text-xs mt-1">{t('account.password.minLength')}</p>
              </div>
              <div>
                <label className="block text-gray-500 dark:text-gray-400 text-sm mb-1">{t('account.password.confirmPassword')}</label>
                <input
                  type="password"
                  value={passwordForm.new_password_confirm}
                  onChange={(e) => setPasswordForm({ ...passwordForm, new_password_confirm: e.target.value })}
                  className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded text-gray-900 dark:text-white focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={changingPassword}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
              >
                {changingPassword ? t('account.password.changing') : t('account.password.submit')}
              </button>
            </form>
          )}

          {/* 2FA Tab */}
          {activeTab === '2fa' && accountInfo && (
            <div className="space-y-6">
              {!accountInfo.totp_enabled ? (
                <>
                  {!setup2FAData ? (
                    <div className="text-center">
                      <p className="text-gray-500 dark:text-gray-400 mb-4">
                        {t('account.twoFactor.description')}
                      </p>
                      <button
                        onClick={handleSetup2FA}
                        disabled={setting2FA}
                        className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                      >
                        {setting2FA ? t('account.twoFactor.settingUp') : t('account.twoFactor.enable')}
                      </button>
                    </div>
                  ) : !showBackupCodes ? (
                    <div className="space-y-4">
                      <div className="text-center">
                        <p className="text-gray-500 dark:text-gray-400 mb-4">
                          {t('account.twoFactor.scanQR')}
                        </p>
                        <div className="inline-block bg-white p-4 rounded">
                          <img
                            src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(setup2FAData.qr_code_url)}`}
                            alt="2FA QR Code"
                            className="w-48 h-48"
                          />
                        </div>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
                        <p className="text-gray-500 dark:text-gray-400 text-sm mb-2">{t('account.twoFactor.manualEntry')}</p>
                        <code className="text-blue-600 dark:text-blue-400 text-sm break-all">{setup2FAData.secret}</code>
                      </div>
                      <form onSubmit={handleEnable2FA} className="space-y-4">
                        <div>
                          <label className="block text-gray-500 dark:text-gray-400 text-sm mb-1">
                            {t('account.twoFactor.enterCode')}
                          </label>
                          <input
                            type="text"
                            value={totpCode}
                            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                            className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded text-gray-900 dark:text-white text-center text-2xl tracking-widest focus:border-blue-500 focus:outline-none"
                            placeholder="000000"
                            maxLength={6}
                            required
                          />
                        </div>
                        <div className="flex gap-2">
                          <button
                            type="submit"
                            disabled={setting2FA || totpCode.length !== 6}
                            className="flex-1 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded disabled:opacity-50"
                          >
                            {setting2FA ? t('account.twoFactor.verifying') : t('account.twoFactor.verifyEnable')}
                          </button>
                          <button
                            type="button"
                            onClick={() => { setSetup2FAData(null); setTotpCode(''); }}
                            className="px-4 py-2 bg-gray-200 dark:bg-gray-600 hover:bg-gray-300 dark:hover:bg-gray-700 text-gray-700 dark:text-white rounded"
                          >
                            {t('common:buttons.cancel')}
                          </button>
                        </div>
                      </form>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="bg-yellow-500/20 border border-yellow-500 p-4 rounded">
                        <h3 className="text-yellow-600 dark:text-yellow-400 font-bold mb-2">{t('account.twoFactor.backupCodes.title')}</h3>
                        <p className="text-yellow-600 dark:text-yellow-300 text-sm mb-4">
                          {t('account.twoFactor.backupCodes.description')}
                        </p>
                        <div className="grid grid-cols-2 gap-2">
                          {setup2FAData.backup_codes.map((code, i) => (
                            <code key={i} className="bg-gray-200 dark:bg-gray-800 px-3 py-1 rounded text-gray-900 dark:text-white font-mono text-center">
                              {code}
                            </code>
                          ))}
                        </div>
                      </div>
                      <button
                        onClick={() => { setSetup2FAData(null); setShowBackupCodes(false); setTotpCode(''); }}
                        className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded"
                      >
                        {t('account.twoFactor.done')}
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <div className="space-y-4">
                  <div className="bg-green-500/20 border border-green-500 p-4 rounded">
                    <p className="text-green-600 dark:text-green-400" dangerouslySetInnerHTML={{ __html: t('account.twoFactor.enabled') }} />
                  </div>
                  <form onSubmit={handleDisable2FA} className="space-y-4">
                    <p className="text-gray-500 dark:text-gray-400">
                      {t('account.twoFactor.disablePrompt')}
                    </p>
                    <div>
                      <label className="block text-gray-500 dark:text-gray-400 text-sm mb-1">{t('login.password')}</label>
                      <input
                        type="password"
                        value={disableForm.password}
                        onChange={(e) => setDisableForm({ ...disableForm, password: e.target.value })}
                        className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded text-gray-900 dark:text-white focus:border-blue-500 focus:outline-none"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-gray-500 dark:text-gray-400 text-sm mb-1">TOTP Code</label>
                      <input
                        type="text"
                        value={disableForm.totp_code}
                        onChange={(e) => setDisableForm({ ...disableForm, totp_code: e.target.value.replace(/\D/g, '').slice(0, 6) })}
                        className="w-full px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded text-gray-900 dark:text-white text-center text-xl tracking-widest focus:border-blue-500 focus:outline-none"
                        placeholder="000000"
                        maxLength={6}
                        required
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={disabling2FA}
                      className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-50"
                    >
                      {disabling2FA ? t('account.twoFactor.disabling') : t('account.twoFactor.disable')}
                    </button>
                  </form>
                </div>
              )}
            </div>
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

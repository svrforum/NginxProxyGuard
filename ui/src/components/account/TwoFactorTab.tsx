import { useTranslation } from 'react-i18next';
import type { AccountInfo, Setup2FAResponse, Disable2FARequest } from '../../api/auth';

interface TwoFactorTabProps {
  accountInfo: AccountInfo;
  setup2FAData: Setup2FAResponse | null;
  setSetup2FAData: (data: Setup2FAResponse | null) => void;
  totpCode: string;
  setTotpCode: (code: string) => void;
  setting2FA: boolean;
  showBackupCodes: boolean;
  setShowBackupCodes: (show: boolean) => void;
  disableForm: Disable2FARequest;
  setDisableForm: (form: Disable2FARequest) => void;
  disabling2FA: boolean;
  onSetup2FA: () => Promise<void>;
  onEnable2FA: (e: React.FormEvent) => Promise<void>;
  onDisable2FA: (e: React.FormEvent) => Promise<void>;
}

export function TwoFactorTab({
  accountInfo,
  setup2FAData,
  setSetup2FAData,
  totpCode,
  setTotpCode,
  setting2FA,
  showBackupCodes,
  setShowBackupCodes,
  disableForm,
  setDisableForm,
  disabling2FA,
  onSetup2FA,
  onEnable2FA,
  onDisable2FA,
}: TwoFactorTabProps) {
  const { t } = useTranslation(['auth', 'common']);
  const enabledHtml = t('account.twoFactor.enabled');

  return (
    <div className="space-y-6">
      {!accountInfo.totp_enabled ? (
        <>
          {!setup2FAData ? (
            <div className="text-center">
              <p className="text-gray-500 dark:text-gray-400 mb-4">
                {t('account.twoFactor.description')}
              </p>
              <button
                onClick={onSetup2FA}
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
              <form onSubmit={onEnable2FA} className="space-y-4">
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
            <p
              className="text-green-600 dark:text-green-400"
              // eslint-disable-next-line react/no-danger
              dangerouslySetInnerHTML={{ __html: enabledHtml }}
            />
          </div>
          <form onSubmit={onDisable2FA} className="space-y-4">
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
  );
}

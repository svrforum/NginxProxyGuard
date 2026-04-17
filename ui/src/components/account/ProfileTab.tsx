import { useTranslation } from 'react-i18next';
import type { AccountInfo, ChangeUsernameRequest } from '../../api/auth';

interface ProfileTabProps {
  accountInfo: AccountInfo;
  formatDate: (dateStr?: string) => string;
  showUsernameForm: boolean;
  setShowUsernameForm: (show: boolean) => void;
  usernameForm: ChangeUsernameRequest;
  setUsernameForm: (form: ChangeUsernameRequest) => void;
  changingUsername: boolean;
  onUsernameChange: (e: React.FormEvent) => Promise<void>;
  onLogout: () => void;
  children?: React.ReactNode;
}

export function ProfileTab({
  accountInfo,
  formatDate,
  showUsernameForm,
  setShowUsernameForm,
  usernameForm,
  setUsernameForm,
  changingUsername,
  onUsernameChange,
  onLogout,
  children,
}: ProfileTabProps) {
  const { t } = useTranslation(['auth', 'common', 'navigation']);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-gray-100 dark:bg-gray-700/50 p-4 rounded">
          <p className="text-gray-500 dark:text-gray-400 text-sm">{t('account.info.username')}</p>
          {!showUsernameForm ? (
            <div className="flex items-center justify-between">
              <p className="text-gray-900 dark:text-white font-medium">{accountInfo.username}</p>
              <button
                onClick={() => {
                  setShowUsernameForm(true);
                  setUsernameForm({ ...usernameForm, new_username: accountInfo.username });
                }}
                className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 text-sm"
              >
                {t('common:buttons.edit')}
              </button>
            </div>
          ) : (
            <form onSubmit={onUsernameChange} className="mt-2 space-y-2">
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
                    setShowUsernameForm(false);
                    setUsernameForm({ current_password: '', new_username: '' });
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
        {children}
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
  );
}

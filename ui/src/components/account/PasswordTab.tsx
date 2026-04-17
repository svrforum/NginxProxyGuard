import { useTranslation } from 'react-i18next';
import type { ChangePasswordRequest } from '../../api/auth';

interface PasswordTabProps {
  passwordForm: ChangePasswordRequest & { new_password_confirm: string };
  setPasswordForm: (form: ChangePasswordRequest & { new_password_confirm: string }) => void;
  changingPassword: boolean;
  onSubmit: (e: React.FormEvent) => Promise<void>;
}

export function PasswordTab({ passwordForm, setPasswordForm, changingPassword, onSubmit }: PasswordTabProps) {
  const { t } = useTranslation(['auth', 'common']);

  return (
    <form onSubmit={onSubmit} className="space-y-4">
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
  );
}

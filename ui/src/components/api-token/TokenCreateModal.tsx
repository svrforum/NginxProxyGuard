import { useTranslation } from 'react-i18next';
import { permissionGroupLabels } from '../../api/api-tokens';
import type { TokenFormData } from './types';

interface PermissionsData {
  permissions: string[];
  groups: Record<string, string[]>;
}

interface TokenCreateModalProps {
  formData: TokenFormData;
  setFormData: React.Dispatch<React.SetStateAction<TokenFormData>>;
  permissionsData?: PermissionsData;
  selectedGroup: string | null;
  setSelectedGroup: (group: string | null) => void;
  isPending: boolean;
  onSubmit: (e: React.FormEvent) => void;
  onCancel: () => void;
}

export function TokenCreateModal({
  formData,
  setFormData,
  permissionsData,
  selectedGroup,
  setSelectedGroup,
  isPending,
  onSubmit,
  onCancel,
}: TokenCreateModalProps) {
  const { t } = useTranslation('settings');

  const handleSelectGroup = (group: string) => {
    if (permissionsData?.groups[group]) {
      setSelectedGroup(group);
      setFormData((prev) => ({
        ...prev,
        permissions: permissionsData.groups[group],
      }));
    }
  };

  const handlePermissionToggle = (perm: string) => {
    setSelectedGroup(null);
    setFormData((prev) => ({
      ...prev,
      permissions: prev.permissions.includes(perm)
        ? prev.permissions.filter((p) => p !== perm)
        : [...prev.permissions, perm],
    }));
  };

  return (
    <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-6 border border-slate-200 dark:border-slate-700">
      <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
        {t('apiTokens.form.createTitle')}
      </h3>
      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            {t('apiTokens.form.tokenName')}
          </label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500"
            placeholder={t('apiTokens.form.tokenNamePlaceholder')}
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
            {t('apiTokens.form.permissionGroups')}
          </label>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
            {Object.keys(permissionGroupLabels).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => handleSelectGroup(key)}
                className={`p-3 rounded-lg border text-left transition-colors ${selectedGroup === key
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500 bg-white dark:bg-slate-700'
                  }`}
              >
                <div className="font-medium text-slate-900 dark:text-white">{t(`apiTokens.permissionGroups.${key}.label`)}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{t(`apiTokens.permissionGroups.${key}.description`)}</div>
              </button>
            ))}
          </div>

          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
            {t('apiTokens.form.individualPermissions')}
          </label>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-h-48 overflow-y-auto p-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700">
            {permissionsData?.permissions.map((perm) => (
              <label
                key={perm}
                className="flex items-center gap-2 text-sm cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={formData.permissions.includes(perm)}
                  onChange={() => handlePermissionToggle(perm)}
                  className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                />
                <span className="text-slate-700 dark:text-slate-300">
                  {t(`apiTokens.permissions.${perm}`, perm)}
                </span>
              </label>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('apiTokens.form.allowedIps')}
            </label>
            <input
              type="text"
              value={formData.allowed_ips}
              onChange={(e) => setFormData((prev) => ({ ...prev, allowed_ips: e.target.value }))}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500"
              placeholder="192.168.1.1, 10.0.0.0/8"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('apiTokens.form.commaSeparated')}</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('apiTokens.form.rateLimit')}
            </label>
            <input
              type="number"
              value={formData.rate_limit}
              onChange={(e) => setFormData((prev) => ({ ...prev, rate_limit: e.target.value }))}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500"
              min="0"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              {t('apiTokens.form.expiresIn')}
            </label>
            <select
              value={formData.expires_in}
              onChange={(e) => setFormData((prev) => ({ ...prev, expires_in: e.target.value }))}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-primary-500"
            >
              <option value="7d">{t('apiTokens.expiration.7days')}</option>
              <option value="30d">{t('apiTokens.expiration.30days')}</option>
              <option value="90d">{t('apiTokens.expiration.90days')}</option>
              <option value="1y">{t('apiTokens.expiration.1year')}</option>
              <option value="never">{t('apiTokens.expiration.never')}</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end gap-3 pt-4">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700"
          >
            {t('apiTokens.buttons.cancel')}
          </button>
          <button
            type="submit"
            disabled={!formData.name || formData.permissions.length === 0 || isPending}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isPending ? t('apiTokens.buttons.creating') : t('apiTokens.createToken')}
          </button>
        </div>
      </form>
    </div>
  );
}

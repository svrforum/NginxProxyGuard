import React from 'react';
import { useTranslation } from 'react-i18next';
import { permissionGroupLabels, type APIToken } from '../../api/api-tokens';
import type { TokenFormData } from './types';

interface PermissionsData {
  permissions: string[];
  groups: Record<string, string[]>;
}

interface TokenListProps {
  tokens: APIToken[];
  permissionsData?: PermissionsData;
  editingToken: string | null;
  editData: Partial<TokenFormData>;
  setEditData: React.Dispatch<React.SetStateAction<Partial<TokenFormData>>>;
  editSelectedGroup: string | null;
  setEditSelectedGroup: (group: string | null) => void;
  updatePending: boolean;
  onStartEdit: (token: APIToken) => void;
  onCancelEdit: () => void;
  onUpdate: (id: string) => void;
  onRevoke: (id: string) => void;
  onDelete: (id: string) => void;
}

export function TokenList({
  tokens,
  permissionsData,
  editingToken,
  editData,
  setEditData,
  editSelectedGroup,
  setEditSelectedGroup,
  updatePending,
  onStartEdit,
  onCancelEdit,
  onUpdate,
  onRevoke,
  onDelete,
}: TokenListProps) {
  const { t } = useTranslation('settings');

  const handleEditSelectGroup = (group: string) => {
    if (permissionsData?.groups[group]) {
      setEditSelectedGroup(group);
      setEditData((prev) => ({
        ...prev,
        permissions: permissionsData.groups[group],
      }));
    }
  };

  const handleEditPermissionToggle = (perm: string, currentPermissions: string[]) => {
    setEditSelectedGroup(null);
    const perms = editData.permissions ?? currentPermissions;
    setEditData((prev) => ({
      ...prev,
      permissions: perms.includes(perm)
        ? perms.filter((p) => p !== perm)
        : [...perms, perm],
    }));
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700 shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
        <thead className="bg-slate-50 dark:bg-slate-900">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('apiTokens.table.name')}
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('apiTokens.table.token')}
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('apiTokens.table.permissions')}
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('apiTokens.table.lastUsed')}
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('apiTokens.table.status')}
            </th>
            <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {t('apiTokens.table.actions')}
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
          {tokens.length === 0 ? (
            <tr>
              <td colSpan={6} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                {t('apiTokens.table.empty')}
              </td>
            </tr>
          ) : (
            tokens.map((token: APIToken) => (
              <React.Fragment key={token.id}>
                <tr className="hover:bg-slate-50 dark:hover:bg-slate-700/50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    {editingToken === token.id ? (
                      <input
                        type="text"
                        value={editData.name ?? token.name}
                        onChange={(e) => setEditData((prev) => ({ ...prev, name: e.target.value }))}
                        className="px-2 py-1 border border-slate-300 dark:border-slate-600 rounded bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm w-full"
                      />
                    ) : (
                      <div className="text-sm font-medium text-slate-900 dark:text-white">
                        {token.name}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <code className="text-sm text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-700 px-2 py-1 rounded">
                      {token.token_prefix}...
                    </code>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-1">
                      {(editingToken === token.id ? (editData.permissions ?? token.permissions) : token.permissions).slice(0, 3).map((perm) => (
                        <span
                          key={perm}
                          className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary-100 text-primary-800 dark:bg-primary-900/30 dark:text-primary-300"
                        >
                          {perm === '*' ? 'All' : perm.split(':')[0]}
                        </span>
                      ))}
                      {(editingToken === token.id ? (editData.permissions ?? token.permissions) : token.permissions).length > 3 && (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-400">
                          +{(editingToken === token.id ? (editData.permissions ?? token.permissions) : token.permissions).length - 3} {t('apiTokens.more')}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-600 dark:text-slate-400">
                    {token.last_used_at ? (
                      <div>
                        <div>{formatDate(token.last_used_at)}</div>
                        {token.last_used_ip && (
                          <div className="text-xs text-slate-500 dark:text-slate-500">{token.last_used_ip}</div>
                        )}
                      </div>
                    ) : (
                      t('apiTokens.status.never')
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {token.is_expired ? (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
                        {t('apiTokens.status.expired')}
                      </span>
                    ) : token.is_active ? (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300">
                        {t('apiTokens.status.active')}
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300">
                        {t('apiTokens.status.revoked')}
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    {editingToken === token.id ? (
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => onUpdate(token.id)}
                          disabled={updatePending}
                          className="text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300"
                        >
                          {t('apiTokens.buttons.save')}
                        </button>
                        <button
                          onClick={onCancelEdit}
                          className="text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300"
                        >
                          {t('apiTokens.buttons.cancel')}
                        </button>
                      </div>
                    ) : (
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => onStartEdit(token)}
                          className="text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                        >
                          {t('apiTokens.buttons.edit')}
                        </button>
                        {token.is_active && !token.is_expired && (
                          <button
                            onClick={() => {
                              if (confirm(t('apiTokens.confirm.revoke'))) {
                                onRevoke(token.id);
                              }
                            }}
                            className="text-yellow-600 hover:text-yellow-700 dark:text-yellow-400 dark:hover:text-yellow-300"
                          >
                            {t('apiTokens.buttons.revoke')}
                          </button>
                        )}
                        <button
                          onClick={() => {
                            if (confirm(t('apiTokens.confirm.delete'))) {
                              onDelete(token.id);
                            }
                          }}
                          className="text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                        >
                          {t('apiTokens.buttons.delete')}
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
                {/* Expanded Edit Form */}
                {editingToken === token.id && (
                  <tr className="bg-slate-50 dark:bg-slate-900">
                    <td colSpan={6} className="px-6 py-4">
                      <div className="space-y-4">
                        {/* Permission Groups */}
                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            {t('apiTokens.form.permissionGroups')}
                          </label>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
                            {Object.keys(permissionGroupLabels).map((key) => (
                              <button
                                key={key}
                                type="button"
                                onClick={() => handleEditSelectGroup(key)}
                                className={`p-3 rounded-lg border text-left transition-colors ${editSelectedGroup === key
                                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                                  : 'border-slate-300 dark:border-slate-600 hover:border-slate-400 dark:hover:border-slate-500 bg-white dark:bg-slate-800'
                                  }`}
                              >
                                <div className="font-medium text-slate-900 dark:text-white text-sm">{t(`apiTokens.permissionGroups.${key}.label`)}</div>
                                <div className="text-xs text-slate-500 dark:text-slate-400">{t(`apiTokens.permissionGroups.${key}.description`)}</div>
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Individual Permissions */}
                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                            {t('apiTokens.form.individualPermissions')}
                          </label>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 max-h-32 overflow-y-auto p-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-800">
                            {permissionsData?.permissions.map((perm) => (
                              <label
                                key={perm}
                                className="flex items-center gap-2 text-sm cursor-pointer"
                              >
                                <input
                                  type="checkbox"
                                  checked={(editData.permissions ?? token.permissions).includes(perm)}
                                  onChange={() => handleEditPermissionToggle(perm, token.permissions)}
                                  className="rounded border-slate-300 dark:border-slate-600 text-primary-600 focus:ring-primary-500"
                                />
                                <span className="text-slate-700 dark:text-slate-300 text-xs">
                                  {t(`apiTokens.permissions.${perm}`, perm)}
                                </span>
                              </label>
                            ))}
                          </div>
                        </div>

                        {/* Allowed IPs and Rate Limit */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                              {t('apiTokens.form.allowedIpsEdit')}
                            </label>
                            <input
                              type="text"
                              value={editData.allowed_ips ?? ''}
                              onChange={(e) => setEditData((prev) => ({ ...prev, allowed_ips: e.target.value }))}
                              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
                              placeholder="192.168.1.1, 10.0.0.0/8"
                            />
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t('apiTokens.form.allowedIpsHelp')}</p>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                              {t('apiTokens.form.rateLimit')}
                            </label>
                            <input
                              type="number"
                              value={editData.rate_limit ?? ''}
                              onChange={(e) => setEditData((prev) => ({ ...prev, rate_limit: e.target.value }))}
                              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
                              placeholder="1000"
                              min="0"
                            />
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

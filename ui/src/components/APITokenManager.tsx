import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  getAPITokens,
  createAPIToken,
  updateAPIToken,
  revokeAPIToken,
  deleteAPIToken,
  getPermissions,
  permissionGroupLabels,
  APIToken,
  CreateAPITokenRequest,
  UpdateAPITokenRequest,
} from '../api/api-tokens';

interface TokenFormData {
  name: string;
  permissions: string[];
  allowed_ips: string;
  rate_limit: string;
  expires_in: string;
}

const initialFormData: TokenFormData = {
  name: '',
  permissions: [],
  allowed_ips: '',
  rate_limit: '1000',
  expires_in: '30d',
};

export default function APITokenManager() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [formData, setFormData] = useState<TokenFormData>(initialFormData);
  const [createdToken, setCreatedToken] = useState<string | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null);
  const [editingToken, setEditingToken] = useState<string | null>(null);
  const [editData, setEditData] = useState<Partial<TokenFormData>>({});
  const [editSelectedGroup, setEditSelectedGroup] = useState<string | null>(null);

  const { data: tokens = [], isLoading } = useQuery({
    queryKey: ['api-tokens'],
    queryFn: () => getAPITokens(),
  });

  const { data: permissionsData } = useQuery({
    queryKey: ['api-permissions'],
    queryFn: getPermissions,
  });

  const createMutation = useMutation({
    mutationFn: createAPIToken,
    onSuccess: (data) => {
      setCreatedToken(data.token);
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
      setFormData(initialFormData);
      setSelectedGroup(null);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateAPITokenRequest }) => updateAPIToken(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
      setEditingToken(null);
      setEditData({});
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => revokeAPIToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteAPIToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    const req: CreateAPITokenRequest = {
      name: formData.name,
      permissions: formData.permissions,
    };
    if (formData.allowed_ips.trim()) {
      req.allowed_ips = formData.allowed_ips.split(',').map((ip) => ip.trim());
    }
    if (formData.rate_limit) {
      req.rate_limit = parseInt(formData.rate_limit, 10);
    }
    if (formData.expires_in && formData.expires_in !== 'never') {
      req.expires_in = formData.expires_in;
    }
    createMutation.mutate(req);
  };

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

  const startEditing = (token: APIToken) => {
    setEditingToken(token.id);
    setEditData({
      name: token.name,
      permissions: token.permissions,
      allowed_ips: token.allowed_ips?.join(', ') ?? '',
      rate_limit: token.rate_limit?.toString() ?? '',
    });
    setEditSelectedGroup(null);
  };

  const handleUpdate = (id: string) => {
    const updateData: UpdateAPITokenRequest = {};
    if (editData.name) updateData.name = editData.name;
    if (editData.permissions && editData.permissions.length > 0) {
      updateData.permissions = editData.permissions;
    }
    if (editData.allowed_ips !== undefined) {
      const trimmed = editData.allowed_ips.trim();
      updateData.allowed_ips = trimmed
        ? trimmed.split(',').map((ip) => ip.trim()).filter(ip => ip)
        : [];
    }
    if (editData.rate_limit) {
      updateData.rate_limit = parseInt(editData.rate_limit, 10);
    }
    updateMutation.mutate({ id, data: updateData });
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Created Token Modal */}
      {createdToken && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-slate-800 rounded-lg p-6 max-w-lg w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
              {t('apiTokens.modal.created')}
            </h3>
            <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mb-4">
              <p className="text-sm text-yellow-800 dark:text-yellow-200 mb-2">
                {t('apiTokens.modal.tokenWarning')}
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-slate-100 dark:bg-slate-700 px-3 py-2 rounded text-sm font-mono break-all text-slate-800 dark:text-slate-200">
                  {createdToken}
                </code>
                <button
                  onClick={() => copyToClipboard(createdToken)}
                  className="px-3 py-2 bg-primary-600 text-white rounded hover:bg-primary-700"
                >
                  {t('apiTokens.buttons.copy')}
                </button>
              </div>
            </div>
            <button
              onClick={() => {
                setCreatedToken(null);
                setShowCreateForm(false);
              }}
              className="w-full px-4 py-2 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-white rounded hover:bg-slate-200 dark:hover:bg-slate-600"
            >
              {t('apiTokens.buttons.close')}
            </button>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('apiTokens.title')}</h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            {t('apiTokens.subtitle')}
            <a
              href="/api/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="ml-2 text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 hover:underline inline-flex items-center gap-1"
            >
              {t('apiTokens.apiDocs')}
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
            </a>
          </p>
        </div>
        {!showCreateForm && (
          <button
            onClick={() => setShowCreateForm(true)}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
          >
            {t('apiTokens.createToken')}
          </button>
        )}
      </div>

      {/* Create Form */}
      {showCreateForm && !createdToken && (
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-6 border border-slate-200 dark:border-slate-700">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">
            {t('apiTokens.form.createTitle')}
          </h3>
          <form onSubmit={handleCreate} className="space-y-4">
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
                onClick={() => {
                  setShowCreateForm(false);
                  setFormData(initialFormData);
                  setSelectedGroup(null);
                }}
                className="px-4 py-2 border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700"
              >
                {t('apiTokens.buttons.cancel')}
              </button>
              <button
                type="submit"
                disabled={!formData.name || formData.permissions.length === 0 || createMutation.isPending}
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {createMutation.isPending ? t('apiTokens.buttons.creating') : t('apiTokens.createToken')}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Token List */}
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
                            onClick={() => handleUpdate(token.id)}
                            disabled={updateMutation.isPending}
                            className="text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300"
                          >
                            {t('apiTokens.buttons.save')}
                          </button>
                          <button
                            onClick={() => {
                              setEditingToken(null);
                              setEditData({});
                              setEditSelectedGroup(null);
                            }}
                            className="text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300"
                          >
                            {t('apiTokens.buttons.cancel')}
                          </button>
                        </div>
                      ) : (
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => startEditing(token)}
                            className="text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
                          >
                            {t('apiTokens.buttons.edit')}
                          </button>
                          {token.is_active && !token.is_expired && (
                            <button
                              onClick={() => {
                                if (confirm(t('apiTokens.confirm.revoke'))) {
                                  revokeMutation.mutate(token.id);
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
                                deleteMutation.mutate(token.id);
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

      {/* Usage Note */}
      <div className="bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800 rounded-lg p-4">
        <h4 className="font-medium text-primary-800 dark:text-primary-200 mb-2">{t('apiTokens.usage.title')}</h4>
        <p className="text-sm text-primary-700 dark:text-primary-300 mb-2">
          {t('apiTokens.usage.description')}
        </p>
        <code className="block bg-primary-100 dark:bg-primary-900 px-3 py-2 rounded text-sm font-mono text-primary-800 dark:text-primary-200">
          Authorization: Bearer ng_your_token_here
        </code>
      </div>
    </div>
  );
}

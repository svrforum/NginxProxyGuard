import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  getAPITokens,
  createAPIToken,
  updateAPIToken,
  revokeAPIToken,
  deleteAPIToken,
  getPermissions,
  APIToken,
  CreateAPITokenRequest,
  UpdateAPITokenRequest,
} from '../api/api-tokens';
import { TokenList } from './api-token/TokenList';
import { TokenCreateModal } from './api-token/TokenCreateModal';
import { CreatedTokenModal, TokenUsageNote } from './api-token/TokenUsageModal';
import { initialFormData, type TokenFormData } from './api-token/types';

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

  const cancelEditing = () => {
    setEditingToken(null);
    setEditData({});
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
        <CreatedTokenModal
          token={createdToken}
          onClose={() => {
            setCreatedToken(null);
            setShowCreateForm(false);
          }}
        />
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
        <TokenCreateModal
          formData={formData}
          setFormData={setFormData}
          permissionsData={permissionsData}
          selectedGroup={selectedGroup}
          setSelectedGroup={setSelectedGroup}
          isPending={createMutation.isPending}
          onSubmit={handleCreate}
          onCancel={() => {
            setShowCreateForm(false);
            setFormData(initialFormData);
            setSelectedGroup(null);
          }}
        />
      )}

      {/* Token List */}
      <TokenList
        tokens={tokens}
        permissionsData={permissionsData}
        editingToken={editingToken}
        editData={editData}
        setEditData={setEditData}
        editSelectedGroup={editSelectedGroup}
        setEditSelectedGroup={setEditSelectedGroup}
        updatePending={updateMutation.isPending}
        onStartEdit={startEditing}
        onCancelEdit={cancelEditing}
        onUpdate={handleUpdate}
        onRevoke={(id) => revokeMutation.mutate(id)}
        onDelete={(id) => deleteMutation.mutate(id)}
      />

      {/* Usage Note */}
      <TokenUsageNote />
    </div>
  );
}

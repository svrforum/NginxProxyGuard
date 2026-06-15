import { Fragment, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ModalShell } from './common/ModalShell';
import { AuthProvider, AuthProviderType, CreateAuthProviderRequest } from '../types/auth-provider';
import { getAuthProviders, createAuthProvider, updateAuthProvider, deleteAuthProvider } from '../api/auth-provider';

interface AuthProviderFormProps {
  provider: AuthProvider | null;
  onClose: () => void;
  onSuccess: () => void;
}

function AuthProviderForm({ provider, onClose, onSuccess }: AuthProviderFormProps) {
  const { t } = useTranslation('authProvider');
  const [name, setName] = useState(provider?.name || '');
  const [type, setType] = useState<AuthProviderType>(provider?.type || 'authelia');
  const [providerUrl, setProviderUrl] = useState(provider?.provider_url || '');
  const [verifyPath, setVerifyPath] = useState(provider?.config?.verify_path || '');
  const [signinMode, setSigninMode] = useState<'location_header' | 'redirect_template'>(provider?.config?.signin_mode || 'location_header');
  const [signinRedirect, setSigninRedirect] = useState(provider?.config?.signin_redirect || '');
  const [cookiePassthrough, setCookiePassthrough] = useState(provider?.config?.cookie_passthrough ?? false);
  const [largeBuffers, setLargeBuffers] = useState(provider?.config?.large_buffers ?? false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const data: CreateAuthProviderRequest = {
        name,
        type,
        provider_url: providerUrl,
        config: type === 'custom'
          ? {
            verify_path: verifyPath || undefined,
            signin_mode: signinMode,
            signin_redirect: signinMode !== 'location_header' ? (signinRedirect || undefined) : undefined,
            cookie_passthrough: cookiePassthrough,
            large_buffers: largeBuffers,
          }
          : undefined,
      };
      if (provider) await updateAuthProvider(provider.id, data);
      else await createAuthProvider(data);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('messages.saveError'));
    } finally {
      setIsSubmitting(false);
    }
  };

  const inputClass = 'w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400';
  const labelClass = 'block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1';

  const helpKey = type === 'authelia' ? 'help.authelia' : type === 'authentik' ? 'help.authentik' : 'help.custom';

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="auth-provider-form-title">
      <div className="p-6">
        <h3 id="auth-provider-form-title" className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">
          {provider ? t('form.editTitle') : t('form.newTitle')}
        </h3>
        {error && (
          <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded mb-4">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={labelClass}>{t('form.name')}</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className={inputClass}
                placeholder={t('form.namePlaceholder')}
              />
            </div>
            <div>
              <label className={labelClass}>{t('form.type')}</label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value as AuthProviderType)}
                className={inputClass}
              >
                <option value="authelia">{t('form.typeAuthelia')}</option>
                <option value="authentik">{t('form.typeAuthentik')}</option>
                <option value="custom">{t('form.typeCustom')}</option>
              </select>
            </div>
          </div>

          <div>
            <label className={labelClass}>{t('form.providerUrl')}</label>
            <input
              type="text"
              value={providerUrl}
              onChange={(e) => setProviderUrl(e.target.value)}
              required
              className={inputClass}
              placeholder={t('form.providerUrlPlaceholder')}
            />
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('help.providerUrl')}</p>
          </div>

          <div className="bg-slate-50 dark:bg-slate-900/30 border border-slate-200 dark:border-slate-700 rounded-md px-3 py-2 text-xs text-slate-600 dark:text-slate-400">
            {t(helpKey)}
          </div>

          {type === 'custom' && (
            <div className="space-y-4 border-l-2 border-indigo-200 dark:border-indigo-800 pl-4">
              <div>
                <label className={labelClass}>{t('form.verifyPath')}</label>
                <input
                  type="text"
                  value={verifyPath}
                  onChange={(e) => setVerifyPath(e.target.value)}
                  className={inputClass}
                  placeholder="/oauth2/auth"
                />
              </div>
              <div>
                <label className={labelClass}>{t('form.signinMode')}</label>
                <select
                  value={signinMode}
                  onChange={(e) => setSigninMode(e.target.value as 'location_header' | 'redirect_template')}
                  className={inputClass}
                >
                  <option value="location_header">{t('form.signinModeLocationHeader')}</option>
                  <option value="redirect_template">{t('form.signinModeRedirectTemplate')}</option>
                </select>
              </div>
              {signinMode !== 'location_header' && (
                <div>
                  <label className={labelClass}>{t('form.signinRedirect')}</label>
                  <input
                    type="text"
                    value={signinRedirect}
                    onChange={(e) => setSigninRedirect(e.target.value)}
                    className={inputClass}
                    placeholder="/oauth2/sign_in?rd=$scheme://$host$request_uri"
                  />
                </div>
              )}
              <div className="flex flex-col gap-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cookiePassthrough}
                    onChange={(e) => setCookiePassthrough(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                  />
                  <span className="text-sm text-slate-700 dark:text-slate-300">{t('form.cookiePassthrough')}</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={largeBuffers}
                    onChange={(e) => setLargeBuffers(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                  />
                  <span className="text-sm text-slate-700 dark:text-slate-300">{t('form.largeBuffers')}</span>
                </label>
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 rounded-md hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
            >
              {t('actions.cancel')}
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              {isSubmitting ? t('actions.save') : provider ? t('actions.update') : t('actions.create')}
            </button>
          </div>
        </form>
      </div>
    </ModalShell>
  );
}

export default function AuthProviderManager() {
  const { t } = useTranslation('authProvider');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<AuthProvider | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['auth-providers'],
    queryFn: () => getAuthProviders(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteAuthProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['auth-providers'] });
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('messages.deleteConfirm'))) {
      deleteMutation.mutate(id);
    }
  };

  const handleEdit = (provider: AuthProvider) => {
    setEditing(provider);
    setShowForm(true);
  };

  const handleClose = () => {
    setShowForm(false);
    setEditing(null);
  };

  const handleSuccess = () => {
    handleClose();
    queryClient.invalidateQueries({ queryKey: ['auth-providers'] });
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded">
        {t('messages.loadError')}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('title')}</h2>
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          + {t('actions.add')}
        </button>
      </div>

      <div className="rounded-lg border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-900/20 px-4 py-3 text-sm text-indigo-900 dark:text-indigo-200">
        <p className="font-semibold mb-1">{t('usage.title')}</p>
        <ol className="list-decimal list-inside space-y-0.5 text-indigo-800 dark:text-indigo-300">
          <li>{t('usage.step1')}</li>
          <li>{t('usage.step2')}</li>
        </ol>
        <p className="mt-1 text-xs text-indigo-700 dark:text-indigo-400">{t('usage.note')}</p>
      </div>

      {showForm && (
        <AuthProviderForm
          provider={editing}
          onClose={handleClose}
          onSuccess={handleSuccess}
        />
      )}

      <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.name')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.type')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.url')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {t('list.empty')}
                </td>
              </tr>
            ) : (
              data?.data?.map((provider) => (
                <Fragment key={provider.id}>
                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="text-sm font-medium text-slate-900 dark:text-white">{provider.name}</div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-0.5 text-xs font-medium rounded bg-indigo-100 dark:bg-indigo-900/30 text-indigo-800 dark:text-indigo-300">
                        {provider.type}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="font-mono text-sm text-slate-700 dark:text-slate-300">{provider.provider_url}</span>
                    </td>
                    <td className="px-6 py-4 text-right space-x-2">
                      <button
                        onClick={() => handleEdit(provider)}
                        className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium"
                      >
                        {t('actions.edit')}
                      </button>
                      <button
                        onClick={() => handleDelete(provider.id)}
                        disabled={deleteMutation.isPending}
                        className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium"
                      >
                        {t('actions.delete')}
                      </button>
                    </td>
                  </tr>
                </Fragment>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

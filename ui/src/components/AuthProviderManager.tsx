import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ModalShell } from './common/ModalShell';
import { AuthProvider, AuthProviderType, CreateAuthProviderRequest } from '../types/auth-provider';
import { getAuthProviders, createAuthProvider, updateAuthProvider, deleteAuthProvider } from '../api/auth-provider';
import { fetchProxyHosts } from '../api/proxy-hosts';
import type { ProxyHost } from '../types/proxy-host';
import { AuthProviderHosts } from './auth-provider/AuthProviderHosts';
import { DockerContainerSelector } from './proxy-host/DockerContainerSelector';

// Per-type accent classes. Full static strings (Tailwind JIT can't see interpolated names).
const ACCENT: Record<string, { icon: string; chip: string }> = {
  authelia: {
    icon: 'bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300',
    chip: 'bg-indigo-50 text-indigo-700 dark:bg-indigo-900/20 dark:text-indigo-300',
  },
  authentik: {
    icon: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-300',
    chip: 'bg-orange-50 text-orange-700 dark:bg-orange-900/20 dark:text-orange-300',
  },
  custom: {
    icon: 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300',
    chip: 'bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300',
  },
};

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
  // Docker-container target (#181). When containerName is set, provider_url is the
  // resolved scheme://ip:port and is auto-re-resolved on IP change by the backend.
  const [containerName, setContainerName] = useState(provider?.container_name || '');
  const [containerNetwork, setContainerNetwork] = useState(provider?.container_network || '');
  const [containerPort, setContainerPort] = useState<number | undefined>(provider?.container_port);
  const [containerScheme, setContainerScheme] = useState(provider?.container_scheme || 'http');
  const [showDockerSelector, setShowDockerSelector] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const isContainer = !!containerName;

  const handlePickContainer = (host: string, port: number, name: string, network: string) => {
    setContainerName(name);
    setContainerNetwork(network);
    setContainerPort(port);
    setProviderUrl(`${containerScheme}://${host}:${port}`);
  };

  const handleClearContainer = () => {
    setContainerName('');
    setContainerNetwork('');
    setContainerPort(undefined);
    // Drop the resolved container IP too, so unbinding forces the operator to enter a
    // real manual address instead of silently saving a now-stale container IP. (#181)
    setProviderUrl('');
  };

  // Rebuild the displayed URL with a new scheme, preserving the resolved host:port.
  const handleSchemeChange = (scheme: string) => {
    setContainerScheme(scheme);
    const hostPort = providerUrl.replace(/^[a-z]+:\/\//i, '');
    setProviderUrl(`${scheme}://${hostPort}`);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const data: CreateAuthProviderRequest = {
        name,
        type,
        provider_url: providerUrl,
        // Container target: send the binding when set; send "" to clear a previously
        // container-backed provider (the backend treats empty name as "unbind").
        container_name: isContainer ? containerName : (provider?.container_name ? '' : undefined),
        container_network: isContainer ? containerNetwork : undefined,
        container_port: isContainer ? containerPort : undefined,
        container_scheme: isContainer ? containerScheme : undefined,
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

  const inputClass = 'w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400';
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
            <div className="flex items-center justify-between mb-1">
              <label className={labelClass + ' mb-0'}>{t('form.providerUrl')}</label>
              {!isContainer && (
                <button
                  type="button"
                  onClick={() => setShowDockerSelector(true)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-indigo-600 hover:text-indigo-700 dark:text-indigo-400 dark:hover:text-indigo-300"
                >
                  <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                  </svg>
                  {t('form.pickContainer')}
                </button>
              )}
            </div>
            {isContainer ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2 rounded-lg border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-900/20 px-3 py-2">
                  <div className="min-w-0 text-xs">
                    <span className="font-medium text-indigo-700 dark:text-indigo-300">🐳 {containerName}</span>
                    <span className="text-indigo-500 dark:text-indigo-400"> · {containerNetwork || '—'}{containerPort ? ` · :${containerPort}` : ''}</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleClearContainer}
                    className="flex-shrink-0 text-xs font-medium text-slate-500 hover:text-red-600 dark:text-slate-400 dark:hover:text-red-400"
                  >
                    {t('form.unbindContainer')}
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <select
                    value={containerScheme}
                    onChange={(e) => handleSchemeChange(e.target.value)}
                    className="px-2 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-700 dark:text-white"
                  >
                    <option value="http">http</option>
                    <option value="https">https</option>
                  </select>
                  <input
                    type="text"
                    value={providerUrl}
                    readOnly
                    className={inputClass + ' font-mono text-xs opacity-80 cursor-not-allowed'}
                  />
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400">{t('help.containerUrl')}</p>
              </div>
            ) : (
              <>
                <input
                  type="text"
                  value={providerUrl}
                  onChange={(e) => setProviderUrl(e.target.value)}
                  required
                  className={inputClass}
                  placeholder={t('form.providerUrlPlaceholder')}
                />
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{t('help.providerUrl')}</p>
              </>
            )}
          </div>

          <DockerContainerSelector
            isOpen={showDockerSelector}
            onClose={() => setShowDockerSelector(false)}
            onSelect={handlePickContainer}
          />

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
              <div className="flex flex-col gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 px-4 py-3">
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
              className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
            >
              {t('actions.cancel')}
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-lg shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition-colors"
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
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['auth-providers'],
    queryFn: () => getAuthProviders(),
  });

  // All proxy hosts, grouped client-side by auth_provider_id for the expand panel.
  const { data: hostsData } = useQuery({
    queryKey: ['proxy-hosts', 'for-auth-providers'],
    queryFn: () => fetchProxyHosts(1, 500),
  });
  const allHosts: ProxyHost[] = hostsData?.data || [];

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
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg shadow-sm hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:focus:ring-offset-slate-900"
        >
          <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
          {t('actions.add')}
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

      {!data?.data?.length ? (
        <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/30 px-6 py-14 text-center">
          <div className="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-400">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400">{t('list.empty')}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {data?.data?.map((provider) => {
            const count = allHosts.filter((h) => h.auth_provider_id === provider.id).length;
            const isOpen = expandedId === provider.id;
            const accent = ACCENT[provider.type] || ACCENT.custom;
            return (
              <div
                key={provider.id}
                className={`group rounded-xl border bg-white dark:bg-slate-800 transition-all ${isOpen ? 'border-indigo-300 dark:border-indigo-700 shadow-sm' : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600'}`}
              >
                <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
                  <button
                    type="button"
                    onClick={() => setExpandedId(isOpen ? null : provider.id)}
                    aria-expanded={isOpen}
                    className="flex flex-1 items-center gap-3 min-w-0 text-left focus:outline-none"
                  >
                    <svg className={`h-4 w-4 shrink-0 text-slate-400 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.2} d="M9 5l7 7-7 7" /></svg>
                    <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${accent.icon}`}>
                      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate text-sm font-semibold text-slate-900 dark:text-white">{provider.name}</span>
                      <span className="block truncate font-mono text-xs text-slate-400 dark:text-slate-500">{provider.provider_url}</span>
                    </span>
                  </button>

                  <span className={`hidden sm:inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${accent.chip}`}>{provider.type}</span>

                  <span
                    className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${count > 0 ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300' : 'bg-slate-100 text-slate-500 dark:bg-slate-700/50 dark:text-slate-400'}`}
                    title={t('hosts.applied')}
                  >
                    <span className={`h-1.5 w-1.5 rounded-full ${count > 0 ? 'bg-emerald-500' : 'bg-slate-400'}`} />
                    {count}
                  </span>

                  <div className="flex items-center gap-0.5">
                    <button
                      onClick={() => handleEdit(provider)}
                      title={t('actions.edit')}
                      aria-label={t('actions.edit')}
                      className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 hover:text-indigo-600 dark:hover:bg-slate-700/60 dark:hover:text-indigo-400 transition-colors"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" /></svg>
                    </button>
                    <button
                      onClick={() => handleDelete(provider.id)}
                      disabled={deleteMutation.isPending}
                      title={t('actions.delete')}
                      aria-label={t('actions.delete')}
                      className="rounded-lg p-2 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/20 dark:hover:text-red-400 transition-colors disabled:opacity-50"
                    >
                      <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                    </button>
                  </div>
                </div>

                <div className={`grid transition-[grid-template-rows] duration-200 ease-out ${isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
                  <div className="overflow-hidden">
                    <div className="border-t border-slate-100 dark:border-slate-700/60">
                      <AuthProviderHosts providerId={provider.id} hosts={allHosts} />
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

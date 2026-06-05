import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { getRedirectHosts, createRedirectHost, updateRedirectHost, deleteRedirectHost } from '../api/access';
import { listCertificates } from '../api/certificates';
import type { RedirectHost, CreateRedirectHostRequest } from '../types/access';
import { useTranslation } from 'react-i18next';
import { HelpTip } from './common/HelpTip';
import { ModalShell } from './common/ModalShell';

interface RedirectHostFormProps {
  redirectHost: RedirectHost | null;
  onClose: () => void;
  onSuccess: () => void;
}

function RedirectHostForm({ redirectHost, onClose, onSuccess }: RedirectHostFormProps) {
  const { t } = useTranslation('redirectHost');
  const [domainNames, setDomainNames] = useState(redirectHost?.domain_names?.join('\n') || '');
  const [forwardScheme, setForwardScheme] = useState(redirectHost?.forward_scheme || 'auto');
  const [forwardDomainName, setForwardDomainName] = useState(redirectHost?.forward_domain_name || '');
  const [forwardPath, setForwardPath] = useState(redirectHost?.forward_path || '');
  const [preservePath, setPreservePath] = useState(redirectHost?.preserve_path ?? true);
  const [redirectCode, setRedirectCode] = useState(redirectHost?.redirect_code || 301);
  const [sslEnabled, setSslEnabled] = useState(redirectHost?.ssl_enabled || false);
  const [certificateId, setCertificateId] = useState(redirectHost?.certificate_id || '');
  const [sslForceHttps, setSslForceHttps] = useState(redirectHost?.ssl_force_https || false);
  const [enabled, setEnabled] = useState(redirectHost?.enabled ?? true);
  const [blockExploits, setBlockExploits] = useState(redirectHost?.block_exploits || false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { data: certificates } = useQuery({
    queryKey: ['certificates'],
    queryFn: () => listCertificates(),
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      const domains = domainNames.split('\n').map(d => d.trim()).filter(Boolean);
      if (domains.length === 0) {
        throw new Error(t('messages.domainRequired'));
      }

      const data: CreateRedirectHostRequest = {
        domain_names: domains,
        forward_scheme: forwardScheme,
        forward_domain_name: forwardDomainName,
        forward_path: forwardPath || undefined,
        preserve_path: preservePath,
        redirect_code: redirectCode,
        ssl_enabled: sslEnabled,
        certificate_id: sslEnabled && certificateId ? certificateId : undefined,
        ssl_force_https: sslForceHttps,
        enabled: enabled,
        block_exploits: blockExploits,
      };

      if (redirectHost) {
        await updateRedirectHost(redirectHost.id, data);
      } else {
        await createRedirectHost(data);
      }
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('messages.saveError'));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="redirect-host-form-title">
        <div className="p-6">
          <h3 id="redirect-host-form-title" className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">
            {redirectHost ? t('form.editTitle') : t('form.newTitle')}
          </h3>

          {error && (
            <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                {t('form.domainNames')}
                <HelpTip contentKey="help.domainNames" ns="redirectHost" />
              </label>
              <textarea
                value={domainNames}
                onChange={(e) => setDomainNames(e.target.value)}
                required
                rows={3}
                className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                placeholder="example.com&#10;www.example.com"
              />
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('form.scheme')}
                  <HelpTip contentKey="help.scheme" ns="redirectHost" />
                </label>
                <select
                  value={forwardScheme}
                  onChange={(e) => setForwardScheme(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white"
                >
                  <option value="auto">{t('form.schemeAuto')}</option>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('form.targetDomain')}
                  <HelpTip contentKey="help.targetDomain" ns="redirectHost" />
                </label>
                <input
                  type="text"
                  value={forwardDomainName}
                  onChange={(e) => setForwardDomainName(e.target.value)}
                  required
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                  placeholder="target.example.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.redirectCode')}</label>
                <select
                  value={redirectCode}
                  onChange={(e) => setRedirectCode(Number(e.target.value))}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white"
                >
                  <option value={301}>301 ({t('form.redirectCodePermanent')})</option>
                  <option value={302}>302 ({t('form.redirectCodeFound')})</option>
                  <option value={307}>307 ({t('form.redirectCodeTemporary')})</option>
                  <option value={308}>308 ({t('form.redirectCodePermanent')})</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('form.forwardPath')}
                  <HelpTip contentKey="help.forwardPath" ns="redirectHost" />
                </label>
                <input
                  type="text"
                  value={forwardPath}
                  onChange={(e) => setForwardPath(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                  placeholder="/optional/path"
                />
              </div>
              <div className="flex items-end pb-2">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={preservePath}
                    onChange={(e) => setPreservePath(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                  />
                  <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                    {t('form.preservePath')}
                    <HelpTip contentKey="help.preservePath" ns="redirectHost" />
                  </span>
                </label>
              </div>
            </div>

            <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
              <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">{t('form.sslConfig')}</h4>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="flex items-center gap-2 mb-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={sslEnabled}
                      onChange={(e) => setSslEnabled(e.target.checked)}
                      className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                    />
                    <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                      {t('form.enableSsl')}
                      <HelpTip contentKey="help.enableSsl" ns="redirectHost" />
                    </span>
                  </label>
                  {sslEnabled && (
                    <select
                      value={certificateId}
                      onChange={(e) => setCertificateId(e.target.value)}
                      className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white"
                    >
                      <option value="">{t('form.selectCertificate')}</option>
                      {certificates?.data?.map((cert) => (
                        <option key={cert.id} value={cert.id}>
                          {cert.domain_names?.join(', ')}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <div className="flex items-start">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={sslForceHttps}
                      onChange={(e) => setSslForceHttps(e.target.checked)}
                      disabled={!sslEnabled}
                      className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700 disabled:opacity-50"
                    />
                    <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                      {t('form.forceHttps')}
                      <HelpTip contentKey="help.forceHttps" ns="redirectHost" />
                    </span>
                  </label>
                </div>
              </div>
            </div>

            <div className="flex gap-6">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                />
                <span className="text-sm text-slate-700 dark:text-slate-300">{t('form.enabled')}</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockExploits}
                  onChange={(e) => setBlockExploits(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                />
                <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.blockExploits')}
                  <HelpTip contentKey="help.blockExploits" ns="redirectHost" />
                </span>
              </label>
            </div>

            <div className="flex justify-end gap-2 pt-4 border-t border-slate-200 dark:border-slate-700">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 rounded-md hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
              >
                {t('form.cancel')}
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 transition-colors"
              >
                {isSubmitting ? t('form.saving') : redirectHost ? t('form.update') : t('form.create')}
              </button>
            </div>
          </form>
        </div>
    </ModalShell>
  );
}

function RedirectCodeBadge({ code }: { code: number }) {
  const colors: Record<number, string> = {
    301: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
    302: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    307: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
    308: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
  };

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${colors[code] || 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300'}`}>
      {code}
    </span>
  );
}

function StatusBadge({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation('redirectHost');
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${enabled ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' : 'bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-300'
      }`}>
      {enabled ? t('badges.active') : t('badges.disabled')}
    </span>
  );
}

export default function RedirectHostManager() {
  const { t } = useTranslation('redirectHost');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingHost, setEditingHost] = useState<RedirectHost | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['redirect-hosts'],
    queryFn: () => getRedirectHosts(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteRedirectHost,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['redirect-hosts'] });
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('messages.deleteConfirm'))) {
      deleteMutation.mutate(id);
    }
  };

  const handleEdit = (host: RedirectHost) => {
    setEditingHost(host);
    setShowForm(true);
  };

  const handleFormClose = () => {
    setShowForm(false);
    setEditingHost(null);
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

  const buildRedirectUrl = (host: RedirectHost) => {
    let url = host.forward_scheme === 'auto' ? '' : `${host.forward_scheme}://`;
    if (host.forward_scheme === 'auto') url = 'https://';
    url += host.forward_domain_name;
    if (host.forward_path) url += host.forward_path;
    if (host.preserve_path) url += '$uri';
    return url;
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('list.title')}</h2>
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          + {t('list.addNew')}
        </button>
      </div>

      {showForm && (
        <RedirectHostForm
          redirectHost={editingHost}
          onClose={handleFormClose}
          onSuccess={() => {
            handleFormClose();
            queryClient.invalidateQueries({ queryKey: ['redirect-hosts'] });
          }}
        />
      )}

      <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.columns.source')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.columns.target')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.columns.code')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.columns.status')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.columns.actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {t('list.empty')}. {t('list.emptyDescription')}
                </td>
              </tr>
            ) : (
              data?.data?.map((host) => (
                <tr key={host.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">
                      {host.domain_names?.join(', ')}
                    </div>
                    <div className="flex gap-1 mt-1">
                      {host.ssl_enabled && (
                        <span className="px-1.5 py-0.5 text-xs bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded">
                          SSL
                        </span>
                      )}
                      {host.block_exploits && (
                        <span className="px-1.5 py-0.5 text-xs bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                          WAF
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-slate-700 dark:text-slate-300 font-mono">
                      {buildRedirectUrl(host)}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <RedirectCodeBadge code={host.redirect_code} />
                  </td>
                  <td className="px-6 py-4">
                    <StatusBadge enabled={host.enabled} />
                  </td>
                  <td className="px-6 py-4 text-right space-x-2">
                    <button
                      onClick={() => handleEdit(host)}
                      className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium"
                    >
                      {t('list.edit')}
                    </button>
                    <button
                      onClick={() => handleDelete(host.id)}
                      disabled={deleteMutation.isPending}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium"
                    >
                      {t('list.delete')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

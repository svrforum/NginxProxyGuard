import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { getRedirectHosts, createRedirectHost, updateRedirectHost, deleteRedirectHost } from '../api/access';
import { listCertificates } from '../api/certificates';
import type { RedirectHost, CreateRedirectHostRequest } from '../types/access';
import { useTranslation } from 'react-i18next';
import { HelpTip } from './common/HelpTip';
import { ModalShell } from './common/ModalShell';
import {
  IconButton,
  AddButton,
  EmptyState,
  StatusPill,
  EntityCard,
  PencilIcon,
  TrashIcon,
  ChevronRightIcon,
} from './common/listui';

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
                className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
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
                  className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
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
                  className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                  placeholder="target.example.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">{t('form.redirectCode')}</label>
                <select
                  value={redirectCode}
                  onChange={(e) => setRedirectCode(Number(e.target.value))}
                  className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
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
                  className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
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

            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 p-4">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">{t('form.sslConfig')}</h4>
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
                      className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
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

            <div className="flex flex-wrap gap-6 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 px-4 py-3">
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
                className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
              >
                {t('form.cancel')}
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-lg shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition-colors"
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

interface RedirectCardProps {
  host: RedirectHost;
  targetUrl: string;
  onEdit: () => void;
  onDelete: () => void;
  deleting: boolean;
}

function RedirectCard({ host, targetUrl, onEdit, onDelete, deleting }: RedirectCardProps) {
  const { t } = useTranslation('redirectHost');
  return (
    <EntityCard>
      <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300">
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 5l7 7-7 7M5 5l7 7-7 7" /></svg>
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-semibold text-slate-900 dark:text-white">
              {host.domain_names?.join(', ')}
            </span>
            <RedirectCodeBadge code={host.redirect_code} />
            {host.ssl_enabled && (
              <span className="inline-flex items-center rounded-md bg-green-50 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-green-700 dark:bg-green-900/20 dark:text-green-300">
                SSL
              </span>
            )}
            {host.block_exploits && (
              <span className="inline-flex items-center rounded-md bg-orange-50 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-orange-700 dark:bg-orange-900/20 dark:text-orange-300">
                WAF
              </span>
            )}
          </div>
          <div className="mt-1 flex items-center gap-1.5 min-w-0">
            <ChevronRightIcon className="h-3.5 w-3.5 shrink-0 text-slate-300 dark:text-slate-600" />
            <span className="truncate font-mono text-xs text-slate-500 dark:text-slate-400">{targetUrl}</span>
          </div>
        </div>

        <StatusPill active={host.enabled}>
          {host.enabled ? t('badges.active') : t('badges.disabled')}
        </StatusPill>

        <div className="flex items-center gap-0.5">
          <IconButton onClick={onEdit} title={t('list.edit')}>
            <PencilIcon />
          </IconButton>
          <IconButton onClick={onDelete} title={t('list.delete')} variant="danger" disabled={deleting}>
            <TrashIcon />
          </IconButton>
        </div>
      </div>
    </EntityCard>
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
        <AddButton onClick={() => setShowForm(true)}>{t('list.addNew')}</AddButton>
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

      {!data?.data?.length ? (
        <EmptyState
          icon={
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M13 5l7 7-7 7M5 5l7 7-7 7" /></svg>
          }
        >
          {t('list.empty')}. {t('list.emptyDescription')}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {data?.data?.map((host) => (
            <RedirectCard
              key={host.id}
              host={host}
              targetUrl={buildRedirectUrl(host)}
              onEdit={() => handleEdit(host)}
              onDelete={() => handleDelete(host.id)}
              deleting={deleteMutation.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

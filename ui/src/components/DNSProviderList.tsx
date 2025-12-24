import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { listDNSProviders, deleteDNSProvider } from '../api/dns-providers';
import { useTranslation } from 'react-i18next';
import type { DNSProvider } from '../types/certificate';
import DNSProviderForm from './DNSProviderForm';

function ProviderTypeBadge({ type }: { type: DNSProvider['provider_type'] }) {
  const { t } = useTranslation('certificates');
  const colors: Record<DNSProvider['provider_type'], string> = {
    cloudflare: 'bg-orange-100 dark:bg-orange-900/30 text-orange-800 dark:text-orange-300',
    route53: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
    duckdns: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
    dynu: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300',
    manual: 'bg-slate-100 dark:bg-slate-700 text-slate-800 dark:text-slate-300',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded-full ${colors[type]}`}>
      {t(`dnsProviders.types.${type}`)}
    </span>
  );
}

export default function DNSProviderList() {
  const { t } = useTranslation('certificates');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingProvider, setEditingProvider] = useState<DNSProvider | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['dns-providers'],
    queryFn: () => listDNSProviders(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteDNSProvider,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dns-providers'] });
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('dnsProviders.confirmDelete'))) {
      deleteMutation.mutate(id);
    }
  };

  const handleEdit = (provider: DNSProvider) => {
    setEditingProvider(provider);
    setShowForm(true);
  };

  const handleFormClose = () => {
    setShowForm(false);
    setEditingProvider(null);
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
      <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded">
        Error loading DNS providers
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('dnsProviders.title')}</h2>
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          + {t('dnsProviders.add')}
        </button>
      </div>

      {showForm && (
        <DNSProviderForm
          provider={editingProvider}
          onClose={handleFormClose}
          onSuccess={() => {
            handleFormClose();
            queryClient.invalidateQueries({ queryKey: ['dns-providers'] });
          }}
        />
      )}

      <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('dnsProviders.name')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('dnsProviders.type')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('dnsProviders.default')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('dnsProviders.credentials')}
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('dnsProviders.actions')}
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-12 text-center text-slate-500 dark:text-slate-400">
                  {t('dnsProviders.empty')}
                </td>
              </tr>
            ) : (
              data?.data?.map((provider) => (
                <tr key={provider.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">{provider.name}</div>
                  </td>
                  <td className="px-6 py-4">
                    <ProviderTypeBadge type={provider.provider_type} />
                  </td>
                  <td className="px-6 py-4">
                    {provider.is_default ? (
                      <span className="px-2 py-1 text-xs font-medium rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300">
                        {t('dnsProviders.default')}
                      </span>
                    ) : (
                      <span className="text-slate-400 text-sm">-</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    {provider.has_credentials ? (
                      <span className="text-green-600 dark:text-green-400 text-sm">{t('dnsProviders.configured')}</span>
                    ) : (
                      <span className="text-yellow-600 dark:text-yellow-400 text-sm">{t('dnsProviders.notConfigured')}</span>
                    )}
                  </td>
                  <td className="px-6 py-4 text-right space-x-2">
                    <button
                      onClick={() => handleEdit(provider)}
                      className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium"
                    >
                      {t('dnsProviders.edit')}
                    </button>
                    <button
                      onClick={() => handleDelete(provider.id)}
                      disabled={deleteMutation.isPending}
                      className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium"
                    >
                      {t('dnsProviders.delete')}
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

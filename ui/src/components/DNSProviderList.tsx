import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { listDNSProviders, deleteDNSProvider } from '../api/dns-providers';
import { useTranslation } from 'react-i18next';
import type { DNSProvider } from '../types/certificate';
import DNSProviderForm from './DNSProviderForm';
import { AddButton, EmptyState, EntityCard, IconButton, PencilIcon, StatusPill, TrashIcon } from './common/listui';

// Per-type accent classes. Full static strings (Tailwind JIT can't see interpolated names).
const ACCENT: Record<DNSProvider['provider_type'], { icon: string; chip: string }> = {
  cloudflare: {
    icon: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-300',
    chip: 'bg-orange-50 text-orange-700 dark:bg-orange-900/20 dark:text-orange-300',
  },
  route53: {
    icon: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
    chip: 'bg-yellow-50 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-300',
  },
  duckdns: {
    icon: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    chip: 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300',
  },
  dynu: {
    icon: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-300',
    chip: 'bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300',
  },
  manual: {
    icon: 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300',
    chip: 'bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300',
  },
};

interface ProviderCardProps {
  provider: DNSProvider;
  onEdit: (provider: DNSProvider) => void;
  onDelete: (id: string) => void;
  deleting: boolean;
}

function ProviderCard({ provider, onEdit, onDelete, deleting }: ProviderCardProps) {
  const { t } = useTranslation('certificates');
  const accent = ACCENT[provider.provider_type] || ACCENT.manual;

  return (
    <EntityCard active={provider.is_default}>
      <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
        <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${accent.icon}`}>
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-semibold text-slate-900 dark:text-white">{provider.name}</span>
            {provider.is_default && <StatusPill active>{t('dnsProviders.default')}</StatusPill>}
          </div>
          <div className="mt-0.5 flex items-center gap-2 text-xs">
            <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${accent.chip}`}>
              {t(`dnsProviders.types.${provider.provider_type}`)}
            </span>
            {provider.has_credentials ? (
              <span className="text-emerald-600 dark:text-emerald-400">{t('dnsProviders.configured')}</span>
            ) : (
              <span className="text-amber-600 dark:text-amber-400">{t('dnsProviders.notConfigured')}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-0.5">
          <IconButton onClick={() => onEdit(provider)} title={t('dnsProviders.edit')}>
            <PencilIcon />
          </IconButton>
          <IconButton
            onClick={() => onDelete(provider.id)}
            disabled={deleting}
            title={t('dnsProviders.delete')}
            variant="danger"
          >
            <TrashIcon />
          </IconButton>
        </div>
      </div>
    </EntityCard>
  );
}

export default function DNSProviderList() {
  const { t } = useTranslation('certificates');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingProvider, setEditingProvider] = useState<DNSProvider | null>(null);
  const [page, setPage] = useState(1);

  const { data, isLoading, error } = useQuery({
    queryKey: ['dns-providers', page],
    queryFn: () => listDNSProviders(page),
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
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded">
        {t('dnsProviders.loadError')}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('dnsProviders.title')}</h2>
        <AddButton onClick={() => setShowForm(true)}>{t('dnsProviders.add')}</AddButton>
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

      {!data?.data?.length ? (
        <EmptyState
          icon={
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        >
          {t('dnsProviders.empty')}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {data?.data?.map((provider) => (
            <ProviderCard
              key={provider.id}
              provider={provider}
              onEdit={handleEdit}
              onDelete={handleDelete}
              deleting={deleteMutation.isPending}
            />
          ))}
        </div>
      )}

      {/* Pagination (#162: list was capped at the first page of 20) */}
      {(data?.total_pages || 1) > 1 && (
        <div className="flex items-center justify-center gap-2 mt-4">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.prev', { defaultValue: '이전' })}
          </button>
          <span className="px-4 py-1.5 text-sm text-slate-600 dark:text-slate-400">
            {page} / {data?.total_pages || 1}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(data?.total_pages || 1, p + 1))}
            disabled={page === (data?.total_pages || 1)}
            className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm disabled:opacity-50 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700"
          >
            {t('pagination.next', { defaultValue: '다음' })}
          </button>
        </div>
      )}
    </div>
  );
}

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { confirmAccessListDNS, deleteAccessList, getAllAccessLists } from '../../api/access';
import { ApiError, isNginxReloadRefusal } from '../../api/client';
import type { AccessList } from '../../types/access';
import { usePermissions } from '../../hooks/usePermissions';
import { usePageVisibility } from '../../hooks/usePageVisibility';
import { AddButton, EmptyState, XIcon } from '../common/listui';
import { DnsConfirmDialog } from '../common/dns/DnsConfirmDialog';
import { dnsNeedsPolling } from '../common/dns/dnsName';
import { AccessListCard } from './AccessListCard';
import { AccessListForm } from './AccessListForm';
import { itemKind } from './accessListItems';
import type { AccessListSaved } from './useAccessListForm';

interface Notice {
  tone: 'amber' | 'red';
  text: string;
  details?: string;
}

const POLL_MS = 10000;

export default function AccessListManager() {
  const { t } = useTranslation(['accessControl', 'common']);
  // Hiding is a convenience; the API refuses writes without access:write.
  const { can } = usePermissions();
  const canWrite = can('access:write');
  const queryClient = useQueryClient();
  const isVisible = usePageVisibility();
  const [showForm, setShowForm] = useState(false);
  const [editingList, setEditingList] = useState<AccessList | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<{ listId: string; hostname: string } | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  // The host form reads the same lists under its own key (useProxyHostFormState).
  const invalidateLists = () => {
    queryClient.invalidateQueries({ queryKey: ['access-lists'] });
    queryClient.invalidateQueries({ queryKey: ['accessLists'] });
  };

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['access-lists'],
    queryFn: getAllAccessLists,
    // Poll only while a domain waits for its first answer, an addition waits
    // for nginx, or a removal has not reached nginx — and only on a visible tab.
    refetchInterval: (query) => {
      if (!isVisible) return false;
      const lists = query.state.data ?? [];
      return dnsNeedsPolling(lists.flatMap((list) => (list.items ?? []).map((item) => item.dns))) ? POLL_MS : false;
    },
  });

  // A 409 nginx_reload_rejected means the change is saved but the running nginx
  // refused it: say so in amber with nginx's own line, and show the saved state.
  const refusalNotice = (key: string, err: ApiError): Notice => ({ tone: 'amber', text: t(key), details: err.details });

  const deleteMutation = useMutation({
    mutationFn: deleteAccessList,
    onSuccess: () => invalidateLists(),
    onError: (err) => {
      invalidateLists();
      setNotice(
        isNginxReloadRefusal(err)
          ? refusalNotice('messages.reloadRejectedDelete', err)
          : { tone: 'red', text: t('messages.deleteError'), details: err instanceof Error ? err.message : undefined },
      );
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('messages.deleteConfirm'))) {
      setNotice(null);
      deleteMutation.mutate(id);
    }
  };

  const handleEdit = (list: AccessList) => {
    setEditingList(list);
    setShowForm(true);
  };

  const handleFormClose = () => {
    setShowForm(false);
    setEditingList(null);
  };

  const handleSaved = ({ refusal }: AccessListSaved) => {
    handleFormClose();
    invalidateLists();
    setNotice(refusal ? refusalNotice('messages.reloadRejectedSave', refusal) : null);
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  // Only a first load that failed replaces the page. A background refetch that
  // fails (the poll, a tab shown again) keeps the lists it had and says so
  // above them, so an open editor or "Allow again" dialog stays as it is.
  if (error && !data) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 px-4 py-3 rounded">
        {t('messages.loadError')}
      </div>
    );
  }

  const lists = data ?? [];
  const target = confirming;
  const confirmStatus = target
    ? lists
        .find((list) => list.id === target.listId)
        ?.items?.find((item) => itemKind(item) === 'hostname' && item.address === target.hostname)?.dns ?? null
    : null;

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('list.title')}</h2>
        {canWrite && <AddButton onClick={() => setShowForm(true)}>{t('actions.add')}</AddButton>}
      </div>

      {error && (
        <div
          role="alert"
          data-testid="access-lists-refresh-error"
          className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300"
        >
          {t('messages.loadError')}
        </div>
      )}

      {notice && (
        <div
          role="status"
          className={`flex items-start gap-3 rounded-lg border px-4 py-3 text-sm ${
            notice.tone === 'amber'
              ? 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800/60 dark:bg-amber-900/20 dark:text-amber-200'
              : 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300'
          }`}
        >
          <div className="min-w-0 flex-1">
            <p>{notice.text}</p>
            {notice.details && <p className="mt-1 break-all font-mono text-xs">{notice.details}</p>}
          </div>
          <button
            type="button"
            onClick={() => setNotice(null)}
            aria-label={t('common:buttons.close')}
            title={t('common:buttons.close')}
            className="rounded p-1 opacity-70 hover:opacity-100"
          >
            <XIcon />
          </button>
        </div>
      )}

      {showForm && <AccessListForm accessList={editingList} onClose={handleFormClose} onSaved={handleSaved} />}

      {target && confirmStatus && (
        <DnsConfirmDialog
          key={`${target.listId}/${target.hostname}`}
          status={confirmStatus}
          onSubmit={(req) => confirmAccessListDNS(target.listId, req)}
          onRefetch={() => void refetch()}
          onFinished={(refusal) => {
            setConfirming(null);
            invalidateLists();
            setNotice(refusal ? refusalNotice('messages.reloadRejectedConfirm', refusal) : null);
          }}
          onClose={() => setConfirming(null)}
        />
      )}

      {lists.length === 0 ? (
        <EmptyState
          icon={
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        >
          {t('list.empty')}
        </EmptyState>
      ) : (
        <div className="space-y-3">
          {lists.map((list) => (
            <AccessListCard
              key={list.id}
              list={list}
              isOpen={expandedId === list.id}
              onToggle={() => setExpandedId(expandedId === list.id ? null : list.id)}
              onEdit={() => handleEdit(list)}
              onDelete={() => handleDelete(list.id)}
              deleting={deleteMutation.isPending}
              canWrite={canWrite}
              onConfirmDns={(hostname) => setConfirming({ listId: list.id, hostname })}
            />
          ))}
        </div>
      )}
    </div>
  );
}

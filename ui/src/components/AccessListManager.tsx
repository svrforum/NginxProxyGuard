import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getAccessLists, createAccessList, updateAccessList, deleteAccessList } from '../api/access';
import type { AccessList, AccessListItem, CreateAccessListRequest } from '../types/access';
import { HelpTip } from './common/HelpTip';
import { ModalShell } from './common/ModalShell';
import {
  AddButton,
  EmptyState,
  EntityCard,
  IconButton,
  PencilIcon,
  TrashIcon,
  ChevronRightIcon,
} from './common/listui';

interface AccessListFormProps {
  accessList: AccessList | null;
  onClose: () => void;
  onSuccess: () => void;
}

function AccessListForm({ accessList, onClose, onSuccess }: AccessListFormProps) {
  const { t } = useTranslation('accessControl');

  const [name, setName] = useState(accessList?.name || '');
  const [description, setDescription] = useState(accessList?.description || '');
  const [satisfyAny, setSatisfyAny] = useState(accessList?.satisfy_any ?? true);
  const [passAuth, setPassAuth] = useState(accessList?.pass_auth ?? false);
  const [items, setItems] = useState<Omit<AccessListItem, 'id' | 'access_list_id' | 'created_at'>[]>(
    accessList?.items?.map(item => ({
      directive: item.directive,
      address: item.address,
      description: item.description,
      sort_order: item.sort_order,
    })) || [{ directive: 'allow', address: '', description: '', sort_order: 0 }]
  );
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleAddItem = () => {
    setItems([...items, { directive: 'allow', address: '', description: '', sort_order: items.length }]);
  };

  const handleRemoveItem = (index: number) => {
    setItems(items.filter((_, i) => i !== index));
  };

  const handleItemChange = (index: number, field: string, value: string) => {
    const newItems = [...items];
    newItems[index] = { ...newItems[index], [field]: value };
    setItems(newItems);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      const data: CreateAccessListRequest = {
        name,
        description: description || undefined,
        satisfy_any: satisfyAny,
        pass_auth: passAuth,
        items: items.filter(item => item.address.trim()).map((item, index) => ({
          directive: item.directive as 'allow' | 'deny',
          address: item.address.trim(),
          description: item.description || undefined,
          sort_order: index,
        })),
      };

      if (accessList) {
        await updateAccessList(accessList.id, data);
      } else {
        await createAccessList(data);
      }
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('messages.saveError'));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="access-list-form-title">
        <div className="p-6">
          <h3 id="access-list-form-title" className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">
            {accessList ? t('form.editTitle') : t('form.newTitle')}
          </h3>

          {error && (
            <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('form.name')}
                  <HelpTip contentKey="help.name" ns="accessControl" />
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                  placeholder={t('form.namePlaceholder')}
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                  {t('form.description')}
                  <HelpTip contentKey="help.description" ns="accessControl" />
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                  placeholder={t('form.descriptionPlaceholder')}
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-6 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 px-4 py-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={satisfyAny}
                  onChange={(e) => setSatisfyAny(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                />
                <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.satisfyAny')}
                  <HelpTip contentKey="help.satisfyAny" ns="accessControl" />
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={passAuth}
                  onChange={(e) => setPassAuth(e.target.checked)}
                  className="rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700"
                />
                <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.passAuth')}
                  <HelpTip contentKey="help.passAuth" ns="accessControl" />
                </span>
              </label>
            </div>

            <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 p-4">
              <div className="flex justify-between items-center mb-3">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-2">
                  {t('form.accessRules')}
                  <HelpTip contentKey="help.accessRules" ns="accessControl" />
                </h4>
                <button
                  type="button"
                  onClick={handleAddItem}
                  className="text-sm text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300 rounded transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  + {t('actions.addRule')}
                </button>
              </div>

              <div className="space-y-2">
                {items.map((item, index) => (
                  <div key={index} className="flex gap-2 items-start">
                    <select
                      value={item.directive}
                      onChange={(e) => handleItemChange(index, 'directive', e.target.value)}
                      className="px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white"
                    >
                      <option value="allow">{t('form.allow')}</option>
                      <option value="deny">{t('form.deny')}</option>
                    </select>
                    <input
                      type="text"
                      value={item.address}
                      onChange={(e) => handleItemChange(index, 'address', e.target.value)}
                      className="flex-1 px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                      placeholder={t('form.ipPlaceholder')}
                    />
                    <input
                      type="text"
                      value={item.description || ''}
                      onChange={(e) => handleItemChange(index, 'description', e.target.value)}
                      className="w-40 px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                      placeholder={t('form.ruleDescription')}
                    />
                    {items.length > 1 && (
                      <button
                        type="button"
                        onClick={() => handleRemoveItem(index)}
                        aria-label={t('actions.removeRule')}
                        title={t('actions.removeRule')}
                        className="p-2 text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

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
                {isSubmitting ? t('actions.save') : accessList ? t('actions.update') : t('actions.create')}
              </button>
            </div>
          </form>
        </div>
    </ModalShell>
  );
}

function DirectiveBadge({ directive }: { directive: 'allow' | 'deny' }) {
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${directive === 'allow'
      ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
      : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
      }`}>
      {directive}
    </span>
  );
}

export default function AccessListManager() {
  const { t } = useTranslation('accessControl');
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingList, setEditingList] = useState<AccessList | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['access-lists'],
    queryFn: () => getAccessLists(),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteAccessList,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-lists'] });
    },
  });

  const handleDelete = (id: string) => {
    if (confirm(t('messages.deleteConfirm'))) {
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
        <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{t('list.title')}</h2>
        <AddButton onClick={() => setShowForm(true)}>{t('actions.add')}</AddButton>
      </div>

      {showForm && (
        <AccessListForm
          accessList={editingList}
          onClose={handleFormClose}
          onSuccess={() => {
            handleFormClose();
            queryClient.invalidateQueries({ queryKey: ['access-lists'] });
          }}
        />
      )}

      {!data?.data?.length ? (
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
          {data.data.map((list) => (
            <AccessListCard
              key={list.id}
              list={list}
              isOpen={expandedId === list.id}
              onToggle={() => setExpandedId(expandedId === list.id ? null : list.id)}
              onEdit={() => handleEdit(list)}
              onDelete={() => handleDelete(list.id)}
              deleting={deleteMutation.isPending}
              t={t}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface AccessListCardProps {
  list: AccessList;
  isOpen: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
  deleting: boolean;
  t: (key: string, opts?: Record<string, unknown>) => string;
}

function AccessListCard({ list, isOpen, onToggle, onEdit, onDelete, deleting, t }: AccessListCardProps) {
  const ruleCount = list.items?.length || 0;
  return (
    <EntityCard active={isOpen}>
      <div className="flex items-center gap-3 px-4 py-3.5 sm:px-5">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={isOpen}
          className="flex flex-1 items-center gap-3 min-w-0 text-left focus:outline-none"
        >
          <ChevronRightIcon
            className={`h-4 w-4 shrink-0 text-slate-400 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
          />
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </span>
          <span className="min-w-0">
            <span className="block truncate text-sm font-semibold text-slate-900 dark:text-white">{list.name}</span>
            {list.description && (
              <span className="block truncate text-xs text-slate-400 dark:text-slate-500">{list.description}</span>
            )}
          </span>
        </button>

        <div className="hidden sm:flex items-center gap-1.5">
          {list.satisfy_any && (
            <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300">
              {t('list.satisfyAny')}
            </span>
          )}
          {list.pass_auth && (
            <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide bg-purple-50 text-purple-700 dark:bg-purple-900/20 dark:text-purple-300">
              {t('list.passAuth')}
            </span>
          )}
        </div>

        <span
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${ruleCount > 0 ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-300' : 'bg-slate-100 text-slate-500 dark:bg-slate-700/50 dark:text-slate-400'}`}
          title={t('list.rules')}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${ruleCount > 0 ? 'bg-emerald-500' : 'bg-slate-400'}`} />
          {ruleCount}
        </span>

        <div className="flex items-center gap-0.5">
          <IconButton onClick={onEdit} title={t('actions.edit')}>
            <PencilIcon />
          </IconButton>
          <IconButton onClick={onDelete} title={t('actions.delete')} disabled={deleting} variant="danger">
            <TrashIcon />
          </IconButton>
        </div>
      </div>

      <div className={`grid transition-[grid-template-rows] duration-200 ease-out ${isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
        <div className="overflow-hidden">
          <div className="border-t border-slate-100 dark:border-slate-700/60 px-4 py-4 sm:px-5 bg-slate-50/60 dark:bg-slate-900/20">
            {ruleCount === 0 ? (
              <p className="text-sm text-slate-400 dark:text-slate-500">{t('list.rulesCount', { count: 0 })}</p>
            ) : (
              <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
                {list.items.map((item, index) => (
                  <div key={item.id || index} className="flex items-center gap-2 text-sm">
                    <DirectiveBadge directive={item.directive} />
                    <span className="font-mono text-slate-700 dark:text-slate-300">{item.address}</span>
                    {item.description && (
                      <span className="text-slate-500 dark:text-slate-400">- {item.description}</span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </EntityCard>
  );
}

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Fragment, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { getAccessLists, createAccessList, updateAccessList, deleteAccessList } from '../api/access';
import type { AccessList, AccessListItem, CreateAccessListRequest } from '../types/access';
import { HelpTip } from './common/HelpTip';
import { ModalShell } from './common/ModalShell';

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
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
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
                  className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                  placeholder={t('form.descriptionPlaceholder')}
                />
              </div>
            </div>

            <div className="flex gap-6">
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

            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center gap-2">
                  {t('form.accessRules')}
                  <HelpTip contentKey="help.accessRules" ns="accessControl" />
                </label>
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
                      className="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white"
                    >
                      <option value="allow">{t('form.allow')}</option>
                      <option value="deny">{t('form.deny')}</option>
                    </select>
                    <input
                      type="text"
                      value={item.address}
                      onChange={(e) => handleItemChange(index, 'address', e.target.value)}
                      className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
                      placeholder={t('form.ipPlaceholder')}
                    />
                    <input
                      type="text"
                      value={item.description || ''}
                      onChange={(e) => handleItemChange(index, 'description', e.target.value)}
                      className="w-40 px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400"
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
                className="px-4 py-2 text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 rounded-md hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
              >
                {t('actions.cancel')}
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 transition-colors"
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
        <button
          onClick={() => setShowForm(true)}
          className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          + {t('actions.add')}
        </button>
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

      <div className="bg-white dark:bg-slate-800 shadow overflow-hidden overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
        <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
          <thead className="bg-slate-50 dark:bg-slate-900/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.name')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.rules')}
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                {t('list.options')}
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
              data?.data?.map((list) => (
                <Fragment key={list.id}>
                  <tr className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="text-sm font-medium text-slate-900 dark:text-white">{list.name}</div>
                      {list.description && (
                        <div className="text-sm text-slate-500 dark:text-slate-400">{list.description}</div>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => setExpandedId(expandedId === list.id ? null : list.id)}
                        className="text-sm text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300"
                      >
                        {t('list.rulesCount', { count: list.items?.length || 0 })} {expandedId === list.id ? t('list.collapse') : t('list.expand')}
                      </button>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        {list.satisfy_any && (
                          <span className="px-2 py-0.5 text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded">
                            {t('list.satisfyAny')}
                          </span>
                        )}
                        {list.pass_auth && (
                          <span className="px-2 py-0.5 text-xs bg-purple-100 dark:bg-purple-900/30 text-purple-800 dark:text-purple-300 rounded">
                            {t('list.passAuth')}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right space-x-2">
                      <button
                        onClick={() => handleEdit(list)}
                        className="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium"
                      >
                        {t('actions.edit')}
                      </button>
                      <button
                        onClick={() => handleDelete(list.id)}
                        disabled={deleteMutation.isPending}
                        className="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 text-sm font-medium"
                      >
                        {t('actions.delete')}
                      </button>
                    </td>
                  </tr>
                  {expandedId === list.id && list.items && list.items.length > 0 && (
                    <tr>
                      <td colSpan={4} className="px-6 py-3 bg-slate-50 dark:bg-slate-900/30">
                        <div className="space-y-1">
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
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

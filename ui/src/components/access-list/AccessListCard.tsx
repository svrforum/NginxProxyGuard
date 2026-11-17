import { useTranslation } from 'react-i18next';
import type { AccessList } from '../../types/access';
import { ChevronRightIcon, EntityCard, IconButton, PencilIcon, TrashIcon } from '../common/listui';
import { DnsEntryStatusList } from '../common/dns/DnsEntryStatusList';
import { DnsLoginBypassWarning } from '../common/dns/DnsLoginBypassWarning';
import { itemKind, legacyEffect } from './accessListItems';

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

interface AccessListCardProps {
  list: AccessList;
  isOpen: boolean;
  onToggle: () => void;
  onEdit: () => void;
  onDelete: () => void;
  deleting: boolean;
  canWrite: boolean;
  /** Opens "Allow again" for a domain of this list. */
  onConfirmDns: (hostname: string) => void;
}

export function AccessListCard({ list, isOpen, onToggle, onEdit, onDelete, deleting, canWrite, onConfirmDns }: AccessListCardProps) {
  const { t } = useTranslation(['accessControl', 'dnsEntries']);
  const items = list.items ?? [];
  const ruleCount = items.length;
  const ruleItems = items.filter((item) => itemKind(item) !== 'hostname');
  const domainItems = items.filter((item) => itemKind(item) === 'hostname');
  const needsReview = domainItems.some((item) => item.dns?.status === 'needs_review');
  const bypass = list.login_bypass_hosts;

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
          {needsReview && (
            <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide bg-orange-50 text-orange-700 dark:bg-orange-900/20 dark:text-orange-300">
              {t('list.needsReview')}
            </span>
          )}
          {list.satisfy_any && (
            <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300">
              {t('list.satisfyAny')}
            </span>
          )}
          {(list.auth_users?.length ?? 0) > 0 && (
            <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
              {t('list.authUsers', { count: list.auth_users?.length ?? 0 })}
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

        {canWrite && (
          <div className="flex items-center gap-0.5">
            <IconButton onClick={onEdit} title={t('actions.edit')}>
              <PencilIcon />
            </IconButton>
            <IconButton onClick={onDelete} title={t('actions.delete')} disabled={deleting} variant="danger">
              <TrashIcon />
            </IconButton>
          </div>
        )}
      </div>

      <div className={`grid transition-[grid-template-rows] duration-200 ease-out ${isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}>
        <div className="overflow-hidden">
          <div className="border-t border-slate-100 dark:border-slate-700/60 px-4 py-4 sm:px-5 bg-slate-50/60 dark:bg-slate-900/20 space-y-4">
            {ruleCount === 0 && (
              <p className="text-sm text-slate-400 dark:text-slate-500">{t('list.rulesCount', { count: 0 })}</p>
            )}
            {ruleItems.length > 0 && (
              <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
                {ruleItems.map((item, index) => (
                  <div key={item.id || index} className="flex flex-wrap items-center gap-2 text-sm">
                    <DirectiveBadge directive={item.directive} />
                    <span className="break-all font-mono text-slate-700 dark:text-slate-300">{item.address}</span>
                    {itemKind(item) === 'legacy' && (
                      <span className="rounded bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300">
                        {legacyEffect(item) === 'deny_all' ? t('form.legacyDenyAll') : t('form.legacyIgnored')}
                      </span>
                    )}
                    {item.description && (
                      <span className="text-slate-500 dark:text-slate-400">- {item.description}</span>
                    )}
                  </div>
                ))}
              </div>
            )}
            {domainItems.length > 0 && (
              <div>
                <h5 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {t('list.domainsTitle')}
                </h5>
                <div className="max-h-96 overflow-y-auto pr-1">
                  <DnsEntryStatusList
                    entries={domainItems.map((item) => ({
                      hostname: item.address,
                      description: item.description,
                      status: item.dns ?? null,
                    }))}
                    canConfirm={canWrite}
                    onConfirm={onConfirmDns}
                  />
                </div>
              </div>
            )}
            {bypass && <DnsLoginBypassWarning count={bypass.count} hosts={bypass.hosts} />}
          </div>
        </div>
      </div>
    </EntityCard>
  );
}

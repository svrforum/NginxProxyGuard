import { useTranslation } from 'react-i18next';
import type { AccessList } from '../../types/access';
import { HelpTip } from '../common/HelpTip';
import { ModalShell } from '../common/ModalShell';
import { DnsLoginBypassWarning } from '../common/dns/DnsLoginBypassWarning';
import { AccessRuleRows } from './AccessRuleRows';
import { AuthUserRows } from './AuthUserRows';
import { LegacyRuleRows } from './LegacyRuleRows';
import { useAccessListForm, type AccessListSaved } from './useAccessListForm';

interface AccessListFormProps {
  accessList: AccessList | null;
  onClose: () => void;
  onSaved: (result: AccessListSaved) => void;
}

const TEXT_INPUT =
  'w-full px-3 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-colors bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400';
const CHECKBOX =
  'rounded border-slate-300 dark:border-slate-600 text-indigo-600 focus:ring-indigo-500 dark:bg-slate-700';

export function AccessListForm({ accessList, onClose, onSaved }: AccessListFormProps) {
  const { t } = useTranslation('accessControl');
  const form = useAccessListForm(accessList, onSaved);
  const bypass = accessList?.login_bypass_hosts;

  return (
    <ModalShell isOpen onClose={onClose} closeOnBackdrop={false} panelClassName="max-w-2xl" labelledById="access-list-form-title">
      <div className="p-6">
        <h3 id="access-list-form-title" className="text-lg font-semibold mb-4 text-slate-900 dark:text-white">
          {accessList ? t('form.editTitle') : t('form.newTitle')}
        </h3>

        {form.formError && (
          <div className="bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400 px-4 py-3 rounded mb-4">
            {form.formError}
          </div>
        )}

        <form onSubmit={form.submit} className="space-y-4">
          {/* E2E fills the name as the first text input of this grid-cols-2 row. */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-2">
                {t('form.name')}
                <HelpTip contentKey="help.name" ns="accessControl" />
              </label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => form.setName(e.target.value)}
                required
                className={TEXT_INPUT}
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
                value={form.description}
                onChange={(e) => form.setDescription(e.target.value)}
                className={TEXT_INPUT}
                placeholder={t('form.descriptionPlaceholder')}
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-6 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-800/40 px-4 py-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.satisfyAny}
                onChange={(e) => form.setSatisfyAny(e.target.checked)}
                className={CHECKBOX}
              />
              <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                {t('form.satisfyAny')}
                <HelpTip contentKey="help.satisfyAny" ns="accessControl" />
              </span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.passAuth}
                onChange={(e) => form.setPassAuth(e.target.checked)}
                className={CHECKBOX}
              />
              <span className="text-sm text-slate-700 dark:text-slate-300 flex items-center gap-2">
                {t('form.passAuth')}
                <HelpTip contentKey="help.passAuth" ns="accessControl" />
              </span>
            </label>
          </div>

          {bypass && form.satisfyAny && <DnsLoginBypassWarning count={bypass.count} hosts={bypass.hosts} />}

          <AccessRuleRows
            rows={form.editableRows}
            errors={form.rowErrors}
            onAdd={form.addRow}
            onChange={form.changeRow}
            onRemove={form.removeRow}
          />

          <LegacyRuleRows
            rows={form.legacyRows}
            errors={form.rowErrors}
            onMove={form.moveToDomain}
            onRemove={form.removeRow}
          />

          <AuthUserRows
            rows={form.users}
            errors={form.userErrors}
            onAdd={form.addUser}
            onChange={form.changeUser}
            onRemove={form.removeUser}
          />

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
              disabled={form.isSubmitting}
              className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-lg shadow-sm hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              {form.isSubmitting ? t('actions.save') : accessList ? t('actions.update') : t('actions.create')}
            </button>
          </div>
        </form>
      </div>
    </ModalShell>
  );
}

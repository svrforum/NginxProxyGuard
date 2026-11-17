import { useTranslation } from 'react-i18next';
import { HelpTip } from '../common/HelpTip';
import { keepsPassword, type AuthUserError, type AuthUserRow } from './authUsers';

interface AuthUserRowsProps {
  rows: AuthUserRow[];
  errors: Record<string, AuthUserError>;
  onAdd: () => void;
  onChange: (key: string, field: 'username' | 'password', value: string) => void;
  onRemove: (key: string) => void;
}

const FIELD =
  'w-full rounded-lg border px-3 py-2.5 transition-colors focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 bg-white dark:bg-slate-700 dark:text-white dark:placeholder-slate-400';
const FIELD_OK = 'border-slate-300 dark:border-slate-600';
const FIELD_BAD = 'border-red-400 dark:border-red-500';

/**
 * The basic auth accounts of the access-list form. It sits after the rule rows:
 * E2E clicks the first button matching "+" for a new rule.
 */
export function AuthUserRows({ rows, errors, onAdd, onChange, onRemove }: AuthUserRowsProps) {
  const { t } = useTranslation('accessControl');

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 dark:border-slate-700 dark:bg-slate-800/40">
      <div className="mb-3 flex items-center justify-between">
        <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {t('form.authUsers')}
          <HelpTip contentKey="help.authUsers" ns="accessControl" />
        </h4>
        <button
          type="button"
          onClick={onAdd}
          className="rounded text-sm text-indigo-600 transition-colors hover:text-indigo-800 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:text-indigo-400 dark:hover:text-indigo-300"
        >
          + {t('actions.addUser')}
        </button>
      </div>

      {rows.length === 0 && <p className="text-sm text-slate-400 dark:text-slate-500">{t('form.authUsersEmpty')}</p>}

      <div className="space-y-2">
        {rows.map((row) => {
          const error = errors[row.key];
          const badName = error === 'usernameRequired' || error === 'usernameInvalid';
          const badPassword = error === 'passwordRequired' || error === 'passwordTooShort';
          return (
            <div key={row.key} data-testid="auth-user-row">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_1fr_auto]">
                <input
                  type="text"
                  value={row.username}
                  onChange={(e) => onChange(row.key, 'username', e.target.value)}
                  placeholder={t('form.username')}
                  aria-label={t('form.username')}
                  autoComplete="off"
                  className={`${FIELD} ${badName ? FIELD_BAD : FIELD_OK}`}
                />
                <input
                  type="password"
                  value={row.password}
                  onChange={(e) => onChange(row.key, 'password', e.target.value)}
                  placeholder={keepsPassword(row) ? t('form.passwordKeep') : t('form.passwordNew')}
                  aria-label={t('form.password')}
                  autoComplete="new-password"
                  className={`${FIELD} ${badPassword ? FIELD_BAD : FIELD_OK}`}
                />
                <button
                  type="button"
                  onClick={() => onRemove(row.key)}
                  className="rounded-lg px-3 py-2 text-sm text-red-600 transition-colors hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-900/20"
                >
                  {t('actions.removeUser')}
                </button>
              </div>
              {error && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{t(`form.userErrors.${error}`)}</p>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { UserEmailRow } from './UserEmailRow'
import { getUserDetail } from '../../api/rbac'
import { ModalShell } from '../common/ModalShell'

interface UserDetailModalProps {
  userId: string | null
  onClose: () => void
}

function fmt(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 text-sm">
      <span className="text-slate-500 dark:text-slate-400">{label}</span>
      <span className="text-right text-slate-800 dark:text-slate-200">{value}</span>
    </div>
  )
}

/**
 * Detail panel for one account: sign-in history, what its role actually reaches,
 * and the API tokens issued under it (#222).
 *
 * The permission list shown is the EFFECTIVE one, not the role's stored rows — a
 * role holding a legacy coarse scope reaches more than it lists, and an
 * administrator holds everything with no rows at all, so the stored list alone
 * would misrepresent the account.
 */
export function UserDetailModal({ userId, onClose }: UserDetailModalProps) {
  const { t } = useTranslation(['settings', 'common'])
  const { data, isLoading, error } = useQuery({
    queryKey: ['user-detail', userId],
    queryFn: () => getUserDetail(userId as string),
    enabled: !!userId,
  })

  const roleLabel = (name: string) =>
    name.startsWith('builtin.')
      ? String(t(`roles.builtin.${name.slice('builtin.'.length)}`, { defaultValue: name }))
      : name || '—'

  return (
    <ModalShell isOpen={!!userId} onClose={onClose} panelClassName="max-w-2xl" labelledById="user-detail-title">
      <div className="p-6">
        <h3 id="user-detail-title" className="text-lg font-semibold text-slate-900 dark:text-white">
          {data ? data.username : t('users.detailTitle')}
        </h3>

        {isLoading && <p className="mt-4 text-sm text-slate-500">{t('common:loading', { defaultValue: 'Loading…' })}</p>}
        {error && (
          <p className="mt-4 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
            {error instanceof Error ? error.message : String(error)}
          </p>
        )}

        {/* No scroll container below: ModalShell's panel already caps height and
            scrolls. A second one nested inside produced two scrollbars. */}
        {data && (
          <div className="mt-4 space-y-5">
            {/* Account */}
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {t('users.sectionAccount')}
              </h4>
              <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
                <Row label={t('users.role')} value={roleLabel(data.role_name)} />
                <UserEmailRow userId={data.id} email={data.email} />
                <Row
                  label={t('users.twoFactor')}
                  value={data.totp_enabled ? t('users.enabled') : t('users.disabled')}
                />
                <Row
                  label={t('users.mustChangePasswordLabel')}
                  value={data.must_change_password ? t('users.yes') : t('users.no')}
                />
                <Row label={t('users.created')} value={fmt(data.created_at)} />
              </div>
            </section>

            {/* Sign-in */}
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {t('users.sectionSignIn')}
              </h4>
              <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
                <Row label={t('users.lastLogin')} value={fmt(data.last_login_at)} />
                <Row
                  label={t('users.lastLoginIP')}
                  value={<span className="font-mono text-xs">{data.last_login_ip || '—'}</span>}
                />
                <Row label={t('users.activeSessions')} value={data.active_sessions} />
              </div>
            </section>

            {/* Sign-in providers (#227) */}
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {t('users.linkedIdentities', { defaultValue: 'Linked sign-in providers' })}
              </h4>
              {(data.linked_identities ?? []).length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">{t('sso.noLinkedIdentities')}</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {(data.linked_identities ?? []).map((idp) => (
                    <span
                      key={idp.provider_slug}
                      className="rounded-lg border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-xs text-indigo-800 dark:border-indigo-900 dark:bg-indigo-900/30 dark:text-indigo-200"
                    >
                      <span className="font-medium">{idp.provider_name}</span>
                      {idp.email && <span className="ml-1.5 font-mono text-[11px] opacity-80">{idp.email}</span>}
                      <span className="ml-1.5 opacity-70">{t('sso.identityLinkedAt', { when: fmt(idp.linked_at) })}</span>
                    </span>
                  ))}
                </div>
              )}
            </section>

            {/* Permissions */}
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {t('users.sectionPermissions')}
              </h4>
              {data.is_superuser ? (
                <p className="rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-700 dark:bg-amber-900/20 dark:text-amber-300">
                  {t('roles.superuserHint')}
                </p>
              ) : (
                <>
                  <p className="mb-2 text-xs text-slate-500 dark:text-slate-400">{t('users.effectiveHint')}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(data.effective_permissions ?? []).length === 0 ? (
                      <span className="text-sm text-slate-500">{t('users.noPermissions')}</span>
                    ) : (
                      (data.effective_permissions ?? []).map((p) => (
                        <span
                          key={p}
                          className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[11px] text-slate-600 dark:bg-slate-700/60 dark:text-slate-300"
                        >
                          {p}
                        </span>
                      ))
                    )}
                  </div>
                </>
              )}
            </section>

            {/* API tokens */}
            <section>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                {t('users.sectionTokens')}
              </h4>
              {(data.tokens ?? []).length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">{t('users.noTokens')}</p>
              ) : (
                <div className="space-y-2">
                  {(data.tokens ?? []).map((tok) => (
                    <div
                      key={tok.id}
                      className="rounded-lg border border-slate-200 px-3 py-2 dark:border-slate-700"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-slate-800 dark:text-slate-100">{tok.name}</span>
                        <span className="font-mono text-[11px] text-slate-400">{tok.token_prefix}…</span>
                        {!tok.is_active && (
                          <span className="rounded-md bg-red-50 px-2 py-0.5 text-[11px] font-semibold uppercase text-red-700 dark:bg-red-900/20 dark:text-red-300">
                            {tok.revoked_at ? t('users.tokenRevoked') : t('users.tokenInactive')}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {tok.permissions.map((p) => (
                          <span
                            key={p}
                            className="rounded bg-indigo-50 px-1.5 py-0.5 font-mono text-[10px] text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-x-3 text-[11px] text-slate-500 dark:text-slate-400">
                        <span>{t('users.tokenLastUsed', { when: fmt(tok.last_used_at) })}</span>
                        {tok.last_used_ip && <span className="font-mono">{tok.last_used_ip}</span>}
                        <span>{t('users.tokenUseCount', { count: tok.use_count })}</span>
                        {tok.expires_at && <span>{t('users.tokenExpires', { when: fmt(tok.expires_at) })}</span>}
                        {!!tok.allowed_ips?.length && (
                          <span className="font-mono">{t('users.tokenAllowedIPs')}: {tok.allowed_ips.join(', ')}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        )}

        <div className="mt-6 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700"
          >
            {t('common:buttons.close')}
          </button>
        </div>
      </div>
    </ModalShell>
  )
}

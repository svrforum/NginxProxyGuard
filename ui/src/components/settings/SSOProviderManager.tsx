import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { createSSOProvider, deleteSSOProvider, listSSOProviders, updateSSOProvider } from '../../api/sso'
import { listRoles } from '../../api/rbac'
import { SSO_SECRET_PLACEHOLDER, type GroupRoleMapping, type SSOProvider, type SSOProviderRequest } from '../../types/sso'
import { usePermissions } from '../../hooks/usePermissions'
import { ModalShell } from '../common/ModalShell'

const emptyForm = (): SSOProviderRequest => ({
  slug: '',
  name: '',
  issuer_url: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid profile email',
  callback_base_url: '',
  enabled: true,
  allow_jit: false,
  allowed_email_domains: [],
  allowed_emails: [],
  group_claim: 'groups',
  required_group: '',
  default_role_id: null,
  group_role_mappings: [],
})

const toForm = (p: SSOProvider): SSOProviderRequest => ({
  slug: p.slug,
  name: p.name,
  issuer_url: p.issuer_url,
  client_id: p.client_id,
  client_secret: SSO_SECRET_PLACEHOLDER,
  scopes: p.scopes,
  callback_base_url: p.callback_base_url ?? '',
  enabled: p.enabled,
  allow_jit: p.allow_jit,
  allowed_email_domains: p.allowed_email_domains ?? [],
  allowed_emails: p.allowed_emails ?? [],
  group_claim: p.group_claim,
  required_group: p.required_group ?? '',
  default_role_id: p.default_role_id,
  group_role_mappings: p.group_role_mappings ?? [],
})

const splitList = (v: string) => v.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)

/**
 * OIDC provider administration (#227).
 *
 * Two things here are load-bearing rather than cosmetic. The callback URL is
 * shown read-only and copyable, because it must match at the identity provider
 * exactly and a typo there fails with an error the operator sees only at the
 * IdP. And automatic account creation is disabled in the form until an
 * allowlist exists, mirroring the server's refusal — a provider like Google
 * authenticates every account in the world.
 */
export function SSOProviderManager() {
  const { t } = useTranslation(['settings', 'common'])
  const tr = (k: string, o?: Record<string, unknown>) => String(t(k, o ?? {}))
  const qc = useQueryClient()
  const { can } = usePermissions()
  // The user area, not settings: a provider decides who may have an account here
  // and with what role, so it is account administration. (#227 security review)
  const canWrite = can('user:write')

  const [editing, setEditing] = useState<SSOProvider | null>(null)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState<SSOProviderRequest>(emptyForm())
  const [formError, setFormError] = useState('')
  const [deleting, setDeleting] = useState<SSOProvider | null>(null)
  const [copied, setCopied] = useState('')

  const { data, isLoading } = useQuery({ queryKey: ['sso-providers'], queryFn: listSSOProviders })
  const { data: rolesData } = useQuery({ queryKey: ['roles'], queryFn: listRoles })
  const providers = data?.data ?? []
  const roles = rolesData?.data ?? []

  const roleLabel = (name: string) =>
    name.startsWith('builtin.') ? tr(`roles.builtin.${name.slice('builtin.'.length)}`, { defaultValue: name }) : name

  const close = () => { setEditing(null); setCreating(false); setFormError('') }

  const save = useMutation({
    mutationFn: async (payload: SSOProviderRequest) =>
      editing ? updateSSOProvider(editing.id, payload) : createSSOProvider(payload),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sso-providers'] }); close() },
    onError: (e: Error) => setFormError(e.message),
  })

  const remove = useMutation({
    mutationFn: (id: string) => deleteSSOProvider(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sso-providers'] }); setDeleting(null) },
  })

  const openCreate = () => { setForm(emptyForm()); setCreating(true); setEditing(null); setFormError('') }
  const openEdit = (p: SSOProvider) => { setForm(toForm(p)); setEditing(p); setCreating(false); setFormError('') }

  const hasAllowlist =
    form.allowed_emails.length > 0 || form.allowed_email_domains.length > 0 || form.required_group.trim() !== ''

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(value)
      setTimeout(() => setCopied(''), 1500)
    } catch {
      /* clipboard is unavailable over plain http; the field is selectable anyway */
    }
  }

  const setMapping = (i: number, patch: Partial<GroupRoleMapping>) =>
    setForm((f) => ({
      ...f,
      group_role_mappings: f.group_role_mappings.map((m, idx) => (idx === i ? { ...m, ...patch } : m)),
    }))

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{tr('sso.title')}</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{tr('sso.subtitle')}</p>
        </div>
        <button
          type="button"
          onClick={openCreate}
          disabled={!canWrite}
          title={canWrite ? undefined : tr('sso.noPermission')}
          className="shrink-0 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-50"
        >
          + {tr('sso.add')}
        </button>
      </div>

      {/* Local password sign-in is never disabled — see the note. */}
      <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-300">
        {tr('sso.localLoginNote')}
      </div>

      {isLoading ? (
        <p className="text-sm text-slate-500">{tr('common:loading', { defaultValue: 'Loading…' })}</p>
      ) : providers.length === 0 ? (
        <p className="rounded-lg border border-dashed border-slate-300 px-4 py-8 text-center text-sm text-slate-500 dark:border-slate-700">
          {tr('sso.empty')}
        </p>
      ) : (
        <div data-testid="sso-provider-list" className="space-y-3">
          {providers.map((p) => (
            <div key={p.id} className="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-900 dark:text-white">{p.name}</span>
                    <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-500 dark:bg-slate-700 dark:text-slate-300">
                      {p.slug}
                    </span>
                    {!p.enabled && (
                      <span className="rounded bg-slate-200 px-2 py-0.5 text-[11px] font-semibold uppercase text-slate-600 dark:bg-slate-600 dark:text-slate-200">
                        {tr('sso.disabled')}
                      </span>
                    )}
                    {p.allow_jit && (
                      <span className="rounded bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">
                        {tr('sso.jitOn')}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 truncate font-mono text-xs text-slate-500 dark:text-slate-400">{p.issuer_url}</p>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {tr('sso.linkedUsers', { count: p.linked_users })}
                  </p>
                </div>
                <div className="flex shrink-0 gap-2">
                  <button
                    type="button"
                    onClick={() => openEdit(p)}
                    className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    {canWrite ? tr('common:buttons.edit') : tr('common:buttons.view', { defaultValue: 'View' })}
                  </button>
                  <button
                    type="button"
                    onClick={() => setDeleting(p)}
                    disabled={!canWrite}
                    title={canWrite ? undefined : tr('sso.noPermission')}
                    className="rounded-lg border border-red-200 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-300 dark:hover:bg-red-900/20"
                  >
                    {tr('common:buttons.delete')}
                  </button>
                </div>
              </div>

              {p.callback_url && (
                <div className="mt-3 rounded-md bg-slate-50 px-3 py-2 dark:bg-slate-900/40">
                  <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">{tr('sso.callbackURL')}</p>
                  <div className="mt-1 flex items-center gap-2">
                    <code className="min-w-0 flex-1 truncate font-mono text-xs text-slate-700 dark:text-slate-300">{p.callback_url}</code>
                    <button
                      type="button"
                      onClick={() => copy(p.callback_url as string)}
                      className="shrink-0 rounded border border-slate-300 px-2 py-0.5 text-[11px] text-slate-600 hover:bg-white dark:border-slate-600 dark:text-slate-300"
                    >
                      {copied === p.callback_url ? tr('sso.copied') : tr('sso.copy')}
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <ModalShell
        isOpen={creating || editing !== null}
        onClose={close}
        closeOnBackdrop={false}
        panelClassName="max-w-2xl"
        labelledById="sso-form-title"
      >
        <div className="p-6">
          <h3 id="sso-form-title" className="text-lg font-semibold text-slate-900 dark:text-white">
            {editing ? tr('sso.editTitle') : tr('sso.addTitle')}
          </h3>

          {formError && (
            <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">{formError}</p>
          )}

          <div className="mt-4 space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={tr('sso.fields.name')}>
                <input aria-label="sso-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputCls} />
              </Field>
              <Field label={tr('sso.fields.slug')} hint={tr('sso.fields.slugHint')}>
                <input aria-label="sso-slug" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} className={inputCls} />
              </Field>
            </div>

            <Field label={tr('sso.fields.issuer')} hint={tr('sso.fields.issuerHint')}>
              <input aria-label="sso-issuer" value={form.issuer_url} onChange={(e) => setForm({ ...form, issuer_url: e.target.value })} className={inputCls} />
            </Field>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={tr('sso.fields.clientId')}>
                <input aria-label="sso-client-id" value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} className={inputCls} />
              </Field>
              <Field label={tr('sso.fields.clientSecret')} hint={editing ? tr('sso.fields.secretKeepHint') : undefined}>
                <input aria-label="sso-client-secret" type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} className={inputCls} />
              </Field>
            </div>

            {editing?.callback_url && (
              <Field label={tr('sso.callbackURL')} hint={tr('sso.callbackHint')}>
                <code className="block truncate rounded-lg bg-slate-100 px-3 py-2 font-mono text-xs text-slate-700 dark:bg-slate-900 dark:text-slate-300">
                  {editing.callback_url}
                </code>
              </Field>
            )}

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={tr('sso.fields.scopes')}>
                <input aria-label="sso-scopes" value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} className={inputCls} />
              </Field>
              <Field label={tr('sso.fields.callbackBase')} hint={tr('sso.fields.callbackBaseHint')}>
                <input aria-label="sso-callback-base" value={form.callback_base_url} onChange={(e) => setForm({ ...form, callback_base_url: e.target.value })} className={inputCls} />
              </Field>
            </div>

            <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
              <input type="checkbox" aria-label="sso-enabled" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} className="rounded" />
              {tr('sso.fields.enabled')}
            </label>

            <hr className="border-slate-200 dark:border-slate-700" />

            <div>
              <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{tr('sso.provisioning')}</h4>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{tr('sso.provisioningHint')}</p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={tr('sso.fields.allowedDomains')} hint={tr('sso.fields.listHint')}>
                <input
                  aria-label="sso-allowed-domains"
                  value={form.allowed_email_domains.join(', ')}
                  onChange={(e) => setForm({ ...form, allowed_email_domains: splitList(e.target.value) })}
                  className={inputCls}
                  placeholder="example.com"
                />
              </Field>
              <Field label={tr('sso.fields.allowedEmails')} hint={tr('sso.fields.listHint')}>
                <input
                  aria-label="sso-allowed-emails"
                  value={form.allowed_emails.join(', ')}
                  onChange={(e) => setForm({ ...form, allowed_emails: splitList(e.target.value) })}
                  className={inputCls}
                  placeholder="admin@example.com"
                />
              </Field>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={tr('sso.fields.groupClaim')}>
                <input aria-label="sso-group-claim" value={form.group_claim} onChange={(e) => setForm({ ...form, group_claim: e.target.value })} className={inputCls} />
              </Field>
              <Field label={tr('sso.fields.requiredGroup')} hint={tr('sso.fields.requiredGroupHint')}>
                <input aria-label="sso-required-group" value={form.required_group} onChange={(e) => setForm({ ...form, required_group: e.target.value })} className={inputCls} />
              </Field>
            </div>

            <label className="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200">
              <input
                type="checkbox"
                aria-label="sso-allow-jit"
                checked={form.allow_jit}
                disabled={!hasAllowlist}
                onChange={(e) => setForm({ ...form, allow_jit: e.target.checked })}
                className="mt-0.5 rounded disabled:opacity-40"
              />
              <span>
                {tr('sso.fields.allowJit')}
                {!hasAllowlist && <span className="mt-0.5 block text-xs text-amber-600 dark:text-amber-400">{tr('sso.jitNeedsAllowlist')}</span>}
              </span>
            </label>

            <Field label={tr('sso.fields.defaultRole')} hint={tr('sso.fields.defaultRoleHint')}>
              <select
                aria-label="sso-default-role"
                value={form.default_role_id ?? ''}
                onChange={(e) => setForm({ ...form, default_role_id: e.target.value || null })}
                className={inputCls}
              >
                <option value="">{tr('sso.fields.noRole')}</option>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>{roleLabel(r.name)}</option>
                ))}
              </select>
            </Field>

            <div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{tr('sso.fields.groupMappings')}</span>
                <button
                  type="button"
                  onClick={() => setForm({ ...form, group_role_mappings: [...form.group_role_mappings, { group: '', role_id: roles[0]?.id ?? '' }] })}
                  className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-300"
                >
                  + {tr('sso.fields.addMapping')}
                </button>
              </div>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {form.group_role_mappings.length > 0 ? tr('sso.mappingsAuthoritative') : tr('sso.mappingsNone')}
              </p>
              <div className="mt-2 space-y-2">
                {form.group_role_mappings.map((m, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <input
                      aria-label={`sso-mapping-group-${i}`}
                      value={m.group}
                      onChange={(e) => setMapping(i, { group: e.target.value })}
                      placeholder={tr('sso.fields.groupPlaceholder')}
                      className={inputCls + ' flex-1'}
                    />
                    <select
                      aria-label={`sso-mapping-role-${i}`}
                      value={m.role_id}
                      onChange={(e) => setMapping(i, { role_id: e.target.value })}
                      className={inputCls + ' flex-1'}
                    >
                      {roles.map((r) => (
                        <option key={r.id} value={r.id}>{roleLabel(r.name)}</option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={() => setForm({ ...form, group_role_mappings: form.group_role_mappings.filter((_, idx) => idx !== i) })}
                      className="rounded border border-slate-300 px-2 py-1.5 text-xs text-slate-500 hover:bg-slate-50 dark:border-slate-600"
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-6 flex justify-end gap-2">
            <button type="button" onClick={close} className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {tr('common:buttons.cancel')}
            </button>
            {canWrite && (
              <button
                type="button"
                onClick={() => { setFormError(''); save.mutate(form) }}
                disabled={save.isPending}
                className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"
              >
                {tr('common:buttons.save')}
              </button>
            )}
          </div>
        </div>
      </ModalShell>

      <ModalShell isOpen={deleting !== null} onClose={() => setDeleting(null)} panelClassName="max-w-md" labelledById="sso-delete-title">
        <div className="p-6">
          <h3 id="sso-delete-title" className="text-lg font-semibold text-slate-900 dark:text-white">{tr('sso.deleteTitle')}</h3>
          <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
            {tr('sso.deleteBody', { name: deleting?.name ?? '', count: deleting?.linked_users ?? 0 })}
          </p>
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" onClick={() => setDeleting(null)} className="rounded-lg px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700">
              {tr('common:buttons.cancel')}
            </button>
            <button
              type="button"
              onClick={() => deleting && remove.mutate(deleting.id)}
              disabled={remove.isPending}
              className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              {tr('common:buttons.delete')}
            </button>
          </div>
        </div>
      </ModalShell>
    </div>
  )
}

const inputCls =
  'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 focus:border-primary-500 focus:ring-2 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-700 dark:text-white'

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-200">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">{hint}</span>}
    </label>
  )
}

export default SSOProviderManager

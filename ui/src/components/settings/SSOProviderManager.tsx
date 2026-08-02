import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { createSSOProvider, deleteSSOProvider, listSSOProviders, testSSODiscovery, updateSSOProvider } from '../../api/sso'
import { listRoles } from '../../api/rbac'
import {
  SSO_PRESETS,
  SSO_SECRET_PLACEHOLDER,
  type GroupRoleMapping,
  type SSODiscoveryResult,
  type SSOProvider,
  type SSOProviderRequest,
} from '../../types/sso'
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

/** Derives a URL-safe identifier from a display name so nobody has to invent one. */
const slugify = (v: string) =>
  v.toLowerCase().trim().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32)

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
  const [preset, setPreset] = useState('generic')
  // Whether the operator has typed a slug themselves. Until they do, the slug
  // follows the display name — nobody should have to invent a URL segment.
  const [slugTouched, setSlugTouched] = useState(false)
  const [probe, setProbe] = useState<{ state: 'idle' | 'busy' | 'ok' | 'error'; result?: SSODiscoveryResult; message?: string }>({ state: 'idle' })

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

  const openCreate = () => {
    setForm(emptyForm()); setCreating(true); setEditing(null); setFormError('')
    setPreset('generic'); setSlugTouched(false); setProbe({ state: 'idle' })
  }
  const openEdit = (p: SSOProvider) => {
    setForm(toForm(p)); setEditing(p); setCreating(false); setFormError('')
    setPreset('generic'); setSlugTouched(true); setProbe({ state: 'idle' })
  }

  const applyPreset = (key: string) => {
    const found = SSO_PRESETS.find((x) => x.key === key)
    if (!found) return
    setPreset(key)
    setProbe({ state: 'idle' })
    setForm((f) => ({
      ...f,
      name: f.name || (key === 'generic' ? '' : found.label),
      slug: slugTouched ? f.slug : slugify(f.name || (key === 'generic' ? '' : found.label)),
      issuer_url: found.issuerTemplate,
      scopes: found.scopes,
      group_claim: found.groupClaim,
    }))
  }

  const setName = (name: string) =>
    setForm((f) => ({ ...f, name, slug: slugTouched ? f.slug : slugify(name) }))

  // The callback URL the server will derive, computed the same way it does, so
  // it can be registered at the provider BEFORE the provider is saved here —
  // Google and Authentik both demand the redirect URI up front.
  const callbackPreview = form.slug
    ? `${(form.callback_base_url || window.location.origin).replace(/\/+$/, '')}/api/v1/auth/sso/${form.slug}/callback`
    : ''

  const runProbe = async () => {
    setProbe({ state: 'busy' })
    try {
      const result = await testSSODiscovery(form.issuer_url, form.scopes)
      setProbe({ state: 'ok', result })
    } catch (e) {
      setProbe({ state: 'error', message: e instanceof Error ? e.message : String(e) })
    }
  }

  // Group rules are silent failures waiting to happen: if the groups claim is
  // never requested, the claim never arrives, every login is refused as "not
  // permitted", and nothing on screen says why. (#227)
  const usesGroups = form.required_group.trim() !== '' || form.group_role_mappings.length > 0
  const groupsScopeMissing = usesGroups && !form.scopes.split(/\s+/).includes('groups')

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

          <div className="mt-4 space-y-5">
            {/* ── 1. Which provider ─────────────────────────────────── */}
            <Step n={1} title={tr('sso.steps.provider')}>
              <div className="flex flex-wrap gap-2">
                {SSO_PRESETS.map((x) => (
                  <button
                    key={x.key}
                    type="button"
                    aria-label={`sso-preset-${x.key}`}
                    onClick={() => applyPreset(x.key)}
                    className={`rounded-lg border px-3 py-1.5 text-sm transition-colors ${
                      preset === x.key
                        ? 'border-primary-500 bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-200'
                        : 'border-slate-300 text-slate-600 hover:bg-slate-50 dark:border-slate-600 dark:text-slate-300 dark:hover:bg-slate-700'
                    }`}
                  >
                    {x.key === 'generic' ? tr('sso.presets.generic') : x.label}
                  </button>
                ))}
              </div>

              {/* What to do AT the provider. The callback URL is inlined rather
                  than referred to, so the step and the value to paste are in the
                  same place. */}
              {preset !== 'generic' && (
                <div data-testid="sso-guide" className="mt-3 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2.5 dark:border-slate-700 dark:bg-slate-900/40">
                  <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                    {tr('sso.guideTitle', { provider: SSO_PRESETS.find((x) => x.key === preset)?.label ?? '' })}
                  </p>
                  <ol className="mt-1.5 list-decimal space-y-1 pl-4 text-xs text-slate-600 dark:text-slate-300">
                    {(t(`sso.guides.${preset}.steps`, { returnObjects: true, defaultValue: [] }) as unknown as string[]).map(
                      (line, i) => (
                        <li key={i}>{renderGuideLine(line, callbackPreview, tr('sso.callbackNeedsSlug'))}</li>
                      ),
                    )}
                  </ol>
                  <p className="mt-2 text-[11px] text-slate-500 dark:text-slate-400">
                    {tr(`sso.guides.${preset}.groups`, { defaultValue: '' })}
                  </p>
                </div>
              )}

              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <Field label={tr('sso.fields.name')}>
                  <input aria-label="sso-name" value={form.name} onChange={(e) => setName(e.target.value)} className={inputCls} />
                </Field>
                <Field label={tr('sso.fields.slug')} hint={tr('sso.fields.slugHint')}>
                  <input
                    aria-label="sso-slug"
                    value={form.slug}
                    onChange={(e) => { setSlugTouched(true); setForm({ ...form, slug: e.target.value }) }}
                    className={inputCls}
                  />
                </Field>
              </div>
            </Step>

            {/* ── 2. Connection, with a way to check it ─────────────── */}
            <Step n={2} title={tr('sso.steps.connection')}>
              <Field label={tr('sso.fields.issuer')} hint={tr(SSO_PRESETS.find((x) => x.key === preset)?.hintKey ?? 'sso.fields.issuerHint')}>
                <div className="flex gap-2">
                  <input
                    aria-label="sso-issuer"
                    value={form.issuer_url}
                    onChange={(e) => { setForm({ ...form, issuer_url: e.target.value }); setProbe({ state: 'idle' }) }}
                    className={inputCls}
                  />
                  <button
                    type="button"
                    aria-label="sso-test"
                    onClick={runProbe}
                    disabled={!form.issuer_url || probe.state === 'busy'}
                    className="shrink-0 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    {probe.state === 'busy' ? tr('sso.testing') : tr('sso.test')}
                  </button>
                </div>
              </Field>

              {probe.state === 'ok' && probe.result && (
                <div data-testid="sso-probe-ok" className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-800 dark:border-emerald-900 dark:bg-emerald-900/20 dark:text-emerald-300">
                  <p className="font-semibold">{tr('sso.testOk')}</p>
                  <p className="mt-1 font-mono break-all">{probe.result.issuer}</p>
                  <p className="mt-0.5">
                    {probe.result.supports_pkce ? tr('sso.testPkceOk') : tr('sso.testPkceUnknown')}
                  </p>
                  {!!probe.result.missing_scopes?.length && (
                    <p className="mt-0.5 text-amber-700 dark:text-amber-300">
                      {tr('sso.testMissingScopes', { scopes: probe.result.missing_scopes.join(', ') })}
                    </p>
                  )}
                </div>
              )}
              {probe.state === 'error' && (
                <div data-testid="sso-probe-error" className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900 dark:bg-red-900/20 dark:text-red-300">
                  {tr('sso.testFailed')}
                </div>
              )}

              {/* Shown BEFORE saving: Google and Authentik want the redirect URI
                  registered while the client is being created. */}
              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-700 dark:bg-slate-900/40">
                <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">{tr('sso.callbackURL')}</p>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{tr('sso.callbackHint')}</p>
                <div className="mt-1.5 flex items-center gap-2">
                  <code data-testid="sso-callback-preview" className="min-w-0 flex-1 truncate font-mono text-xs text-slate-700 dark:text-slate-300">
                    {callbackPreview || tr('sso.callbackNeedsSlug')}
                  </code>
                  <button
                    type="button"
                    onClick={() => callbackPreview && copy(callbackPreview)}
                    disabled={!callbackPreview}
                    className="shrink-0 rounded border border-slate-300 px-2 py-0.5 text-[11px] text-slate-600 hover:bg-white disabled:opacity-40 dark:border-slate-600 dark:text-slate-300"
                  >
                    {copied && copied === callbackPreview ? tr('sso.copied') : tr('sso.copy')}
                  </button>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <Field label={tr('sso.fields.clientId')}>
                  <input aria-label="sso-client-id" value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} className={inputCls} />
                </Field>
                <Field label={tr('sso.fields.clientSecret')} hint={editing ? tr('sso.fields.secretKeepHint') : undefined}>
                  <input aria-label="sso-client-secret" type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} className={inputCls} />
                </Field>
              </div>

              <details className="rounded-lg border border-slate-200 px-3 py-2 dark:border-slate-700">
                <summary className="cursor-pointer text-xs font-medium text-slate-600 dark:text-slate-300">{tr('sso.advanced')}</summary>
                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <Field label={tr('sso.fields.scopes')}>
                    <input aria-label="sso-scopes" value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} className={inputCls} />
                  </Field>
                  <Field label={tr('sso.fields.callbackBase')} hint={tr('sso.fields.callbackBaseHint')}>
                    <input aria-label="sso-callback-base" value={form.callback_base_url} onChange={(e) => setForm({ ...form, callback_base_url: e.target.value })} className={inputCls} />
                  </Field>
                </div>
              </details>

              <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200">
                <input type="checkbox" aria-label="sso-enabled" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} className="rounded" />
                {tr('sso.fields.enabled')}
              </label>
            </Step>

            {/* ── 3. Who gets in, and as what ──────────────────────── */}
            <Step n={3} title={tr('sso.steps.access')}>
              <p className="text-xs text-slate-500 dark:text-slate-400">{tr('sso.provisioningHint')}</p>

              {groupsScopeMissing && (
                <div data-testid="sso-groups-scope-warning" className="flex flex-wrap items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-300">
                  <span className="flex-1">{tr('sso.groupsScopeMissing')}</span>
                  <button
                    type="button"
                    aria-label="sso-add-groups-scope"
                    onClick={() => setForm((f) => ({ ...f, scopes: `${f.scopes.trim()} groups`.trim() }))}
                    className="shrink-0 rounded border border-amber-400 px-2 py-0.5 font-medium text-amber-900 hover:bg-amber-100 dark:border-amber-700 dark:text-amber-200"
                  >
                    {tr('sso.addGroupsScope')}
                  </button>
                </div>
              )}

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
            </Step>
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

/** Splits a guide step on the {{callback}} placeholder and renders the real URL
 *  inline as copyable code, so the instruction and the value never drift apart. */
function renderGuideLine(line: string, callback: string, fallback: string) {
  const parts = line.split('{{callback}}')
  if (parts.length === 1) return line
  return parts.flatMap((part, i) =>
    i === 0
      ? [part]
      : [
          <code
            key={`cb-${i}`}
            className="mx-0.5 rounded bg-white px-1 py-0.5 font-mono text-[11px] break-all text-slate-700 dark:bg-slate-800 dark:text-slate-200"
          >
            {callback || fallback}
          </code>,
          part,
        ],
  )
}

/** A numbered section. The form asks for twelve things; presenting them as three
 *  ordered steps is what turns a wall of inputs into a task. */
function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-200 p-4 dark:border-slate-700">
      <div className="mb-3 flex items-center gap-2">
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary-600 text-xs font-semibold text-white">
          {n}
        </span>
        <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h4>
      </div>
      <div className="space-y-3">{children}</div>
    </section>
  )
}

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

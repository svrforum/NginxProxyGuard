// OIDC SSO types (#227).
//
// Not to be confused with the ForwardAuth provider types: those protect proxied
// hosts, these let someone sign in to this panel.

/** All an unauthenticated login screen is told about a provider. */
export interface PublicSSOProvider {
  id: string
  slug: string
  name: string
}

export interface GroupRoleMapping {
  group: string
  role_id: string
}

export interface SSOProvider {
  id: string
  slug: string
  name: string
  issuer_url: string
  client_id: string
  /** Always the masked marker on read; send it back unchanged to keep the
   *  stored secret, or a new value to replace it. */
  client_secret?: string
  scopes: string
  callback_base_url: string
  enabled: boolean
  allow_jit: boolean
  allowed_email_domains: string[] | null
  allowed_emails: string[] | null
  group_claim: string
  required_group: string
  default_role_id: string | null
  group_role_mappings: GroupRoleMapping[] | null
  /** Derived by the server — the exact redirect_uri to register at the IdP. */
  callback_url?: string
  linked_users: number
  created_at: string
  updated_at: string
}

export interface SSOProviderRequest {
  slug: string
  name: string
  issuer_url: string
  client_id: string
  client_secret: string
  scopes: string
  callback_base_url: string
  enabled: boolean
  allow_jit: boolean
  allowed_email_domains: string[]
  allowed_emails: string[]
  group_claim: string
  required_group: string
  default_role_id: string | null
  group_role_mappings: GroupRoleMapping[]
}

/** The marker the API substitutes for a stored client secret. */
export const SSO_SECRET_PLACEHOLDER = '********'

/** What an issuer advertises, reported by the Test button. */
export interface SSODiscoveryResult {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  scopes_supported: string[] | null
  supports_pkce: boolean
  missing_scopes: string[] | null
}

/**
 * Starting points for the providers people actually run.
 *
 * The issuer is the one field nobody remembers and every provider writes
 * differently — Google publishes a fixed URL, Authentik buries the application
 * slug in the path, Keycloak the realm. Filling it as a template with the parts
 * to replace made obvious is the difference between "paste your issuer" and a
 * support question.
 */
export interface SSOPreset {
  key: string
  label: string
  issuerTemplate: string
  scopes: string
  groupClaim: string
  /** Shown under the issuer field while this preset is selected. */
  hintKey: string
}

export const SSO_PRESETS: SSOPreset[] = [
  {
    key: 'google',
    label: 'Google',
    issuerTemplate: 'https://accounts.google.com',
    scopes: 'openid profile email',
    groupClaim: 'groups',
    hintKey: 'sso.presets.googleHint',
  },
  {
    key: 'authentik',
    label: 'Authentik',
    issuerTemplate: 'https://authentik.example.com/application/o/<application-slug>/',
    scopes: 'openid profile email',
    groupClaim: 'groups',
    hintKey: 'sso.presets.authentikHint',
  },
  {
    key: 'authelia',
    label: 'Authelia',
    issuerTemplate: 'https://auth.example.com',
    scopes: 'openid profile email groups',
    groupClaim: 'groups',
    hintKey: 'sso.presets.autheliaHint',
  },
  {
    key: 'keycloak',
    label: 'Keycloak',
    issuerTemplate: 'https://keycloak.example.com/realms/<realm>',
    scopes: 'openid profile email',
    groupClaim: 'groups',
    hintKey: 'sso.presets.keycloakHint',
  },
  {
    key: 'generic',
    label: 'OpenID Connect',
    issuerTemplate: '',
    scopes: 'openid profile email',
    groupClaim: 'groups',
    hintKey: 'sso.presets.genericHint',
  },
]

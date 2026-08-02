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

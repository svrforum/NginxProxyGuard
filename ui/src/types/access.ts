export interface AccessListItem {
  id: string;
  access_list_id: string;
  directive: 'allow' | 'deny';
  address: string;
  description?: string;
  sort_order: number;
  created_at: string;
}

export interface AccessList {
  id: string;
  name: string;
  description?: string;
  satisfy_any: boolean;
  pass_auth: boolean;
  items: AccessListItem[];
  created_at: string;
  updated_at: string;
}

export interface CreateAccessListRequest {
  name: string;
  description?: string;
  satisfy_any?: boolean;
  pass_auth?: boolean;
  items?: {
    directive: 'allow' | 'deny';
    address: string;
    description?: string;
    sort_order?: number;
  }[];
}

export interface RedirectHost {
  id: string;
  domain_names: string[];
  forward_scheme: string;
  forward_domain_name: string;
  forward_path: string;
  preserve_path: boolean;
  redirect_code: number;
  ssl_enabled: boolean;
  certificate_id?: string;
  ssl_force_https: boolean;
  enabled: boolean;
  block_exploits: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRedirectHostRequest {
  domain_names: string[];
  forward_scheme?: string;
  forward_domain_name: string;
  forward_path?: string;
  preserve_path?: boolean;
  redirect_code?: number;
  ssl_enabled?: boolean;
  certificate_id?: string;
  ssl_force_https?: boolean;
  enabled?: boolean;
  block_exploits?: boolean;
}

export interface GeoRestriction {
  id: string;
  proxy_host_id: string;
  mode: 'whitelist' | 'blacklist';
  countries: string[];
  allowed_ips: string[];
  allow_private_ips: boolean;
  allow_search_bots: boolean;
  enabled: boolean;
  challenge_mode: boolean;
  disable_global: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateGeoRestrictionRequest {
  mode: 'whitelist' | 'blacklist';
  countries: string[];
  allowed_ips?: string[];
  allow_private_ips?: boolean;
  allow_search_bots?: boolean;
  enabled?: boolean;
  challenge_mode?: boolean;
  disable_global?: boolean;
}

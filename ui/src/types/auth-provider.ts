export type AuthProviderType = 'authelia' | 'authentik' | 'custom';

export interface AuthHeader { name: string; value: string }
export interface AuthResponseHeader { var: string; upstream: string; forward: string }

export interface AuthProviderConfig {
  verify_path?: string;
  request_headers?: AuthHeader[];
  response_headers?: AuthResponseHeader[];
  signin_mode?: 'location_header' | 'redirect_template';
  signin_redirect?: string;
  public_paths?: string[];
  cookie_passthrough?: boolean;
  large_buffers?: boolean;
}

export interface AuthProvider {
  id: string;
  name: string;
  type: AuthProviderType;
  provider_url: string;
  config: AuthProviderConfig;
  timeout_ms: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateAuthProviderRequest {
  name: string;
  type: AuthProviderType;
  provider_url: string;
  config?: AuthProviderConfig;
  timeout_ms?: number;
  enabled?: boolean;
}

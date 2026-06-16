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

// Docker-container target for the verify endpoint (#181). When container_name is
// set, provider_url is the resolved scheme://ip:port and is re-resolved on IP change.
export interface AuthProviderContainerTarget {
  container_name?: string;
  container_network?: string;
  container_port?: number;
  container_scheme?: string;
}

// Read-only container-reconcile health (#181 follow-up). Set by the backend scheduler.
export interface AuthProviderReconcileStatus {
  last_resolved_ip?: string;
  last_reconcile_at?: string;
  last_reconcile_status?: 'ok' | 'failed';
  last_reconcile_error?: string;
  reconcile_fail_count?: number;
}

export interface AuthProvider extends AuthProviderContainerTarget, AuthProviderReconcileStatus {
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

export interface CreateAuthProviderRequest extends AuthProviderContainerTarget {
  name: string;
  type: AuthProviderType;
  provider_url: string;
  config?: AuthProviderConfig;
  timeout_ms?: number;
  enabled?: boolean;
}

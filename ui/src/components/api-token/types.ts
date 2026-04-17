// Shared type for the local form state across api-token sub-components.
export interface TokenFormData {
  name: string;
  permissions: string[];
  allowed_ips: string;
  rate_limit: string;
  expires_in: string;
}

export const initialFormData: TokenFormData = {
  name: '',
  permissions: [],
  allowed_ips: '',
  rate_limit: '1000',
  expires_in: '30d',
};

import { apiGet } from './client';

/** What the header shows about this NPG (#369). Any signed-in role may read it. */
export interface InstanceInfo {
  version: string;
  nginx_version?: string;
  instance_name: string;
}

export async function getInstanceInfo(): Promise<InstanceInfo> {
  return apiGet<InstanceInfo>('/api/v1/instance');
}

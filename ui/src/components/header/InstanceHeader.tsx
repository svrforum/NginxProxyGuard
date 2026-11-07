import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getInstanceInfo } from '../../api/instance';

// The header's instance name and nginx version (#369). Both read one query.
function useInstanceInfo() {
  return useQuery({ queryKey: ['instance'], queryFn: getInstanceInfo, staleTime: 5 * 60 * 1000 });
}

/** The instance name beside the logo. The browser tab carries it too. */
export function InstanceNameBadge() {
  const name = useInstanceInfo().data?.instance_name;
  useEffect(() => {
    document.title = name ? `${name} · Nginx Proxy Guard` : 'Nginx Proxy Guard';
  }, [name]);
  if (!name) return null;
  return (
    <span
      data-testid="instance-name"
      title={name}
      className="max-w-[9rem] sm:max-w-[14rem] truncate rounded-md bg-primary-50 px-2 py-0.5 text-xs font-semibold text-primary-700 ring-1 ring-primary-200 dark:bg-primary-900/30 dark:text-primary-300 dark:ring-primary-800"
    >
      {name}
    </span>
  );
}

/** NPG's version, and nginx's under it when the API could read it. */
export function HeaderVersion({ version }: { version?: string }) {
  const nginxVersion = useInstanceInfo().data?.nginx_version;
  return (
    <div className="text-right text-xs leading-tight text-slate-400">
      <div>v{version || '...'}</div>
      {nginxVersion && <div data-testid="nginx-version">nginx {nginxVersion}</div>}
    </div>
  );
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getRateLimit, updateRateLimit } from '../../api/security';
import type { CreateRateLimitRequest } from '../../types/security';
import type { SecurityTabProps } from './types';

export default function RateLimitTab({ proxyHostId }: SecurityTabProps) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['rate-limit', proxyHostId],
    queryFn: () => getRateLimit(proxyHostId),
  });

  const mutation = useMutation({
    mutationFn: (data: CreateRateLimitRequest) => updateRateLimit(proxyHostId, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rate-limit', proxyHostId] }),
  });

  const [form, setForm] = useState({
    enabled: false,
    requests_per_second: 10,
    burst_size: 20,
    zone_size: '10m',
    limit_by: 'ip',
    limit_response: 429,
    whitelist_ips: '',
  });

  // Update form when data loads
  if (data && !form.enabled && data.enabled) {
    setForm({
      enabled: data.enabled,
      requests_per_second: data.requests_per_second,
      burst_size: data.burst_size,
      zone_size: data.zone_size,
      limit_by: data.limit_by,
      limit_response: data.limit_response,
      whitelist_ips: data.whitelist_ips || '',
    });
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(form);
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
          className="rounded border-gray-300"
        />
        <span className="font-medium">{t('form.protection.rateLimit.enabled')}</span>
      </label>

      {form.enabled && (
        <>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Requests per Second
              </label>
              <input
                type="number"
                value={form.requests_per_second}
                onChange={(e) => setForm({ ...form, requests_per_second: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={1}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Burst Size
              </label>
              <input
                type="number"
                value={form.burst_size}
                onChange={(e) => setForm({ ...form, burst_size: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
                min={0}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Zone Size</label>
              <select
                value={form.zone_size}
                onChange={(e) => setForm({ ...form, zone_size: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="5m">5 MB</option>
                <option value="10m">10 MB</option>
                <option value="20m">20 MB</option>
                <option value="50m">50 MB</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Limit By</label>
              <select
                value={form.limit_by}
                onChange={(e) => setForm({ ...form, limit_by: e.target.value })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value="ip">IP Address</option>
                <option value="uri">URI</option>
                <option value="ip_uri">IP + URI</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Response Code</label>
              <select
                value={form.limit_response}
                onChange={(e) => setForm({ ...form, limit_response: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border rounded-md"
              >
                <option value={429}>429 Too Many Requests</option>
                <option value={503}>503 Service Unavailable</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Whitelist IPs (CIDR, comma-separated)
            </label>
            <textarea
              value={form.whitelist_ips}
              onChange={(e) => setForm({ ...form, whitelist_ips: e.target.value })}
              className="w-full px-3 py-2 border rounded-md"
              rows={2}
              placeholder="192.168.1.0/24, 10.0.0.1"
            />
          </div>
        </>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
      >
        {mutation.isPending ? 'Saving...' : 'Save'}
      </button>
      {mutation.isError && (
        <p className="text-xs text-red-600 dark:text-red-400">
          {mutation.error instanceof Error ? mutation.error.message : 'Save failed'}
        </p>
      )}

    </form>
  );
}

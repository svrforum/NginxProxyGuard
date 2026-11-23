import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { listBannedIPs, banIP, unbanIP } from '../../api/security';
import type { BanIPRequest } from '../../types/security';
import type { SecurityTabProps } from './types';
import { formatDateTime } from '../../utils/dateTime';

export default function BannedIPsTab({ proxyHostId }: SecurityTabProps) {
  const { t } = useTranslation('proxyHost');
  const queryClient = useQueryClient();
  const [newIP, setNewIP] = useState('');
  const [reason, setReason] = useState('');
  const [banTime, setBanTime] = useState(3600);

  const { data, isLoading } = useQuery({
    queryKey: ['banned-ips', proxyHostId],
    queryFn: () => listBannedIPs(proxyHostId),
  });

  const banMutation = useMutation({
    mutationFn: (req: BanIPRequest) => banIP(req),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] });
      setNewIP('');
      setReason('');
    },
  });

  const unbanMutation = useMutation({
    mutationFn: unbanIP,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['banned-ips'] }),
  });

  const handleBan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIP) return;
    banMutation.mutate({
      proxy_host_id: proxyHostId,
      ip_address: newIP,
      reason,
      ban_time: banTime,
    });
  };

  if (isLoading) return <div className="text-center py-4">{t('common:status.loading')}</div>;

  return (
    <div className="space-y-4">
      <form onSubmit={handleBan} className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.bannedIPs.ip')}</label>
          <input
            type="text"
            value={newIP}
            onChange={(e) => setNewIP(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="192.168.1.100"
          />
        </div>
        <div className="flex-1">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.bannedIPs.reason')}</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Manual ban"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('form.protection.bannedIPs.duration')}</label>
          <select
            value={banTime}
            onChange={(e) => setBanTime(parseInt(e.target.value))}
            className="px-3 py-2 border rounded-md"
          >
            <option value={3600}>{t('form.protection.bannedIPs.durationOptions.1hour')}</option>
            <option value={86400}>{t('form.protection.bannedIPs.durationOptions.1day')}</option>
            <option value={604800}>{t('form.protection.bannedIPs.durationOptions.1week')}</option>
            <option value={0}>{t('form.protection.bannedIPs.durationOptions.permanent')}</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={banMutation.isPending}
          className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
        >
          {banMutation.isPending ? t('form.protection.bannedIPs.banning') : t('form.protection.bannedIPs.ban')}
        </button>
      </form>

      <div className="border dark:border-slate-700 rounded-md overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-slate-700">
          <thead className="bg-gray-50 dark:bg-slate-900">
            <tr>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.ip')}</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.reason')}</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.bannedAt')}</th>
              <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">{t('form.protection.bannedIPs.expiresAt')}</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-slate-700">
            {data?.data?.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500 dark:text-gray-400">
                  {t('form.protection.bannedIPs.empty')}
                </td>
              </tr>
            ) : (
              data?.data?.map((ip) => (
                <tr key={ip.id}>
                  <td className="px-4 py-2 text-sm font-mono">{ip.ip_address}</td>
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">{ip.reason || '-'}</td>
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">
                    {formatDateTime(ip.banned_at)}
                  </td>
                  <td className="px-4 py-2 text-sm">
                    {ip.is_permanent ? (
                      <span className="text-red-600 font-medium">{t('form.protection.bannedIPs.permanent')}</span>
                    ) : ip.expires_at ? (
                      formatDateTime(ip.expires_at)
                    ) : '-'}
                  </td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => unbanMutation.mutate(ip.id)}
                      disabled={unbanMutation.isPending}
                      className="text-sm text-indigo-600 hover:text-indigo-800"
                    >
                      {t('form.protection.bannedIPs.unban')}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

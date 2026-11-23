import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import type { BannedIP } from '../../types/security';
import { listBannedIPs, banIP, unbanIP } from '../../api/security';
import type { SettingsTabProps } from './types';
import { formatDateTime } from '../../utils/dateTime';

export default function BannedIPsSettings({ hostId, queryClient }: SettingsTabProps) {
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['banned-ips', hostId],
    queryFn: () => listBannedIPs(hostId, 1, 100),
  });

  const [newIP, setNewIP] = useState('');
  const [reason, setReason] = useState('');
  const [banTime, setBanTime] = useState(3600);

  const banMutation = useMutation({
    mutationFn: () => banIP({ proxy_host_id: hostId, ip_address: newIP, reason, ban_time: banTime }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips', hostId] });
      setNewIP('');
      setReason('');
      alert('IP banned successfully!');
    },
    onError: (err) => alert(`Error: ${err.message}`),
  });

  const unbanMutation = useMutation({
    mutationFn: (id: string) => unbanIP(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips', hostId] });
      alert('IP unbanned successfully!');
    },
    onError: (err) => alert(`Error: ${err.message}`),
  });

  if (isLoading) return <div className="text-center py-8">Loading...</div>;

  const bannedIPs = data?.data || [];

  return (
    <div className="space-y-6">
      <div>
        <h3 className="font-medium text-slate-900 dark:text-white">Banned IPs</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">Manage manually banned IP addresses</p>
      </div>

      {/* Add new ban */}
      <div className="p-4 bg-slate-50 dark:bg-slate-700/50 rounded-lg space-y-4">
        <h4 className="font-medium text-slate-800 dark:text-slate-200">Ban New IP</h4>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">IP Address</label>
            <input
              type="text"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              placeholder="192.168.1.100"
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Ban Duration</label>
            <select
              value={banTime}
              onChange={(e) => setBanTime(Number(e.target.value))}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            >
              <option value={3600}>1 Hour</option>
              <option value={86400}>1 Day</option>
              <option value={604800}>1 Week</option>
              <option value={2592000}>1 Month</option>
              <option value={0}>Permanent</option>
            </select>
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Reason (optional)</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Manual ban - suspicious activity"
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
          />
        </div>
        <button
          onClick={() => banMutation.mutate()}
          disabled={!newIP || banMutation.isPending}
          className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
        >
          {banMutation.isPending ? 'Banning...' : 'Ban IP'}
        </button>
      </div>

      {/* Banned IPs list */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h4 className="font-medium text-slate-800 dark:text-slate-200">Currently Banned ({bannedIPs.length})</h4>
          <button
            onClick={() => refetch()}
            className="text-sm text-primary-600 hover:text-primary-700"
          >
            Refresh
          </button>
        </div>

        {bannedIPs.length === 0 ? (
          <div className="text-center py-8 text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
            No banned IPs
          </div>
        ) : (
          <div className="border border-slate-200 dark:border-slate-700 rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
              <thead className="bg-slate-50 dark:bg-slate-900">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400">IP Address</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400">Reason</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-slate-500 dark:text-slate-400">Expires</th>
                  <th className="px-4 py-2 text-right text-xs font-medium text-slate-500 dark:text-slate-400">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                {bannedIPs.map((ban: BannedIP) => (
                  <tr key={ban.id}>
                    <td className="px-4 py-2 text-sm font-mono break-all max-w-[18rem]" title={ban.ip_address}>{ban.ip_address}</td>
                    <td className="px-4 py-2 text-sm text-slate-600 dark:text-slate-400">{ban.reason || '-'}</td>
                    <td className="px-4 py-2 text-sm text-slate-600 dark:text-slate-400">
                      {ban.is_permanent ? (
                        <span className="text-red-600 font-medium">Permanent</span>
                      ) : ban.expires_at ? (
                        formatDateTime(ban.expires_at)
                      ) : '-'}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => unbanMutation.mutate(ban.id)}
                        disabled={unbanMutation.isPending}
                        className="text-sm text-red-600 hover:text-red-700"
                      >
                        Unban
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

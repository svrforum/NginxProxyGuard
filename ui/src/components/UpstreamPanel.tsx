import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { getUpstream, updateUpstream, getUpstreamHealth } from '../api/security';
import type { CreateUpstreamRequest } from '../types/security';

interface UpstreamPanelProps {
  proxyHostId: string;
  onClose: () => void;
}

export default function UpstreamPanel({ proxyHostId, onClose }: UpstreamPanelProps) {
  const queryClient = useQueryClient();
  const [showAddServer, setShowAddServer] = useState(false);

  const { data: upstream, isLoading } = useQuery({
    queryKey: ['upstream', proxyHostId],
    queryFn: () => getUpstream(proxyHostId),
  });

  const { data: health } = useQuery({
    queryKey: ['upstream-health', upstream?.id],
    queryFn: () => getUpstreamHealth(upstream!.id),
    enabled: !!upstream?.id && upstream?.health_check_enabled,
    refetchInterval: 60000, // Refresh every 30 seconds
  });

  const mutation = useMutation({
    mutationFn: (data: CreateUpstreamRequest) => updateUpstream(proxyHostId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['upstream', proxyHostId] });
    },
  });

  const [form, setForm] = useState<CreateUpstreamRequest>({
    name: '',
    load_balance: 'round_robin',
    health_check_enabled: false,
    health_check_interval: 30,
    health_check_timeout: 5,
    health_check_path: '/',
    health_check_expected_status: 200,
    keepalive: 32,
    servers: [],
  });

  const [newServer, setNewServer] = useState({
    address: '',
    port: 80,
    weight: 1,
    max_fails: 3,
    fail_timeout: 30,
    is_backup: false,
  });

  // Sync form with upstream data
  if (upstream && form.name === '' && upstream.name) {
    setForm({
      name: upstream.name,
      load_balance: upstream.load_balance,
      health_check_enabled: upstream.health_check_enabled,
      health_check_interval: upstream.health_check_interval,
      health_check_timeout: upstream.health_check_timeout,
      health_check_path: upstream.health_check_path,
      health_check_expected_status: upstream.health_check_expected_status,
      keepalive: upstream.keepalive,
      servers: upstream.servers?.map((s) => ({
        address: s.address,
        port: s.port,
        weight: s.weight,
        max_fails: s.max_fails,
        fail_timeout: s.fail_timeout,
        is_backup: s.is_backup,
        is_down: s.is_down,
      })) || [],
    });
  }

  const handleAddServer = () => {
    if (!newServer.address) return;
    setForm({
      ...form,
      servers: [...(form.servers || []), newServer],
    });
    setNewServer({
      address: '',
      port: 80,
      weight: 1,
      max_fails: 3,
      fail_timeout: 30,
      is_backup: false,
    });
    setShowAddServer(false);
  };

  const handleRemoveServer = (index: number) => {
    setForm({
      ...form,
      servers: form.servers?.filter((_, i) => i !== index),
    });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(form);
  };

  if (isLoading) {
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white dark:bg-slate-800 rounded-lg p-8 dark:text-white">Loading...</div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] overflow-hidden m-4">
        <div className="flex items-center justify-between p-4 border-b dark:border-slate-700">
          <h2 className="text-lg font-semibold dark:text-white">Upstream / Load Balancing</h2>
          <button onClick={onClose} className="text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 overflow-y-auto max-h-[calc(90vh-120px)] space-y-4">
          {/* Health Status */}
          {health && (
            <div className={`p-3 rounded-md ${health.is_healthy ? 'bg-green-50' : 'bg-red-50'}`}>
              <div className="flex items-center justify-between">
                <span className={`font-medium ${health.is_healthy ? 'text-green-700' : 'text-red-700'}`}>
                  {health.is_healthy ? 'Healthy' : 'Unhealthy'}
                </span>
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {health.healthy_count} / {health.healthy_count + health.unhealthy_count} servers up
                </span>
              </div>
              {health.last_check_at && (
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Last check: {new Date(health.last_check_at).toLocaleString()}
                </p>
              )}
            </div>
          )}

          {/* Basic Settings */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
              <input
                type="text"
                value={form.name || ''}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                placeholder="upstream_backend"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Load Balance</label>
              <select
                value={form.load_balance}
                onChange={(e) => setForm({ ...form, load_balance: e.target.value })}
                className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              >
                <option value="round_robin">Round Robin</option>
                <option value="least_conn">Least Connections</option>
                <option value="ip_hash">IP Hash</option>
                <option value="random">Random</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Keepalive Connections
            </label>
            <input
              type="number"
              value={form.keepalive || 32}
              onChange={(e) => setForm({ ...form, keepalive: parseInt(e.target.value) })}
              className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
              min={0}
            />
          </div>

          {/* Health Check Settings */}
          <div className="border dark:border-slate-600 rounded-md p-4 space-y-3">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.health_check_enabled || false}
                onChange={(e) => setForm({ ...form, health_check_enabled: e.target.checked })}
                className="rounded border-gray-300"
              />
              <span className="font-medium dark:text-white">Enable Health Check</span>
            </label>

            {form.health_check_enabled && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Interval (sec)</label>
                  <input
                    type="number"
                    value={form.health_check_interval || 30}
                    onChange={(e) => setForm({ ...form, health_check_interval: parseInt(e.target.value) })}
                    className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                    min={5}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Timeout (sec)</label>
                  <input
                    type="number"
                    value={form.health_check_timeout || 5}
                    onChange={(e) => setForm({ ...form, health_check_timeout: parseInt(e.target.value) })}
                    className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                    min={1}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Health Check Path</label>
                  <input
                    type="text"
                    value={form.health_check_path || '/'}
                    onChange={(e) => setForm({ ...form, health_check_path: e.target.value })}
                    className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                    placeholder="/health"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Expected Status</label>
                  <input
                    type="number"
                    value={form.health_check_expected_status || 200}
                    onChange={(e) => setForm({ ...form, health_check_expected_status: parseInt(e.target.value) })}
                    className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Servers */}
          <div className="border dark:border-slate-600 rounded-md">
            <div className="flex items-center justify-between p-3 border-b dark:border-slate-600 bg-gray-50 dark:bg-slate-700">
              <h4 className="font-medium dark:text-white">Backend Servers</h4>
              <button
                type="button"
                onClick={() => setShowAddServer(true)}
                className="text-sm text-indigo-600 hover:text-indigo-800"
              >
                + Add Server
              </button>
            </div>

            {showAddServer && (
              <div className="p-3 border-b dark:border-slate-600 bg-indigo-50 dark:bg-indigo-900/20 space-y-3">
                <div className="grid grid-cols-4 gap-2">
                  <div className="col-span-2">
                    <input
                      type="text"
                      value={newServer.address}
                      onChange={(e) => setNewServer({ ...newServer, address: e.target.value })}
                      className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                      placeholder="192.168.1.10 or hostname"
                    />
                  </div>
                  <div>
                    <input
                      type="number"
                      value={newServer.port}
                      onChange={(e) => setNewServer({ ...newServer, port: parseInt(e.target.value) })}
                      className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                      placeholder="Port"
                    />
                  </div>
                  <div>
                    <input
                      type="number"
                      value={newServer.weight}
                      onChange={(e) => setNewServer({ ...newServer, weight: parseInt(e.target.value) })}
                      className="w-full px-3 py-2 border dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                      placeholder="Weight"
                    />
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={newServer.is_backup}
                      onChange={(e) => setNewServer({ ...newServer, is_backup: e.target.checked })}
                      className="rounded border-gray-300"
                    />
                    <span className="text-sm dark:text-slate-300">Backup server</span>
                  </label>
                  <div className="space-x-2">
                    <button
                      type="button"
                      onClick={() => setShowAddServer(false)}
                      className="px-3 py-1 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={handleAddServer}
                      className="px-3 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700"
                    >
                      Add
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className="divide-y dark:divide-slate-600">
              {(form.servers || []).length === 0 ? (
                <p className="p-4 text-center text-gray-500 dark:text-gray-400 text-sm">No servers configured</p>
              ) : (
                form.servers?.map((server, index) => {
                  const healthStatus = health?.servers?.find(
                    (s) => s.address === server.address && s.port === server.port
                  );
                  return (
                    <div key={index} className="p-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {healthStatus && (
                          <span
                            className={`w-2 h-2 rounded-full ${
                              healthStatus.is_healthy ? 'bg-green-500' : 'bg-red-500'
                            }`}
                          />
                        )}
                        <span className="font-mono text-sm dark:text-white">
                          {server.address}:{server.port}
                        </span>
                        <span className="text-xs text-gray-500 dark:text-gray-400">weight: {server.weight}</span>
                        {server.is_backup && (
                          <span className="px-1.5 py-0.5 text-xs bg-yellow-100 text-yellow-700 rounded">
                            backup
                          </span>
                        )}
                        {server.is_down && (
                          <span className="px-1.5 py-0.5 text-xs bg-red-100 text-red-700 rounded">
                            down
                          </span>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveServer(index)}
                        className="text-sm text-red-600 hover:text-red-800"
                      >
                        Remove
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-4 border-t dark:border-slate-700">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-slate-700 rounded-md hover:bg-gray-200 dark:hover:bg-slate-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50"
            >
              {mutation.isPending ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

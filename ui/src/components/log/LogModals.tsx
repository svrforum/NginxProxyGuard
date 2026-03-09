import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { updateLogSettings, cleanupLogs } from '../../api/logs';
import { disableWAFRuleByHost } from '../../api/waf';
import { banIP } from '../../api/security';
import type { Log, LogSettings } from '../../types/log';
import { LogTypeBadge, StatusCodeBadge, MethodBadge } from './LogBadges';
import { formatBytes, formatTime } from './LogUtils';
import { useEscapeKey } from '../../hooks/useEscapeKey';

interface LogDetailModalProps {
  log: Log;
  onClose: () => void;
  onRuleDisabled?: () => void;
}

export function LogDetailModal({ log, onClose, onRuleDisabled }: LogDetailModalProps) {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const [disableReason, setDisableReason] = useState('');
  const [showDisableForm, setShowDisableForm] = useState(false);
  const [showBanForm, setShowBanForm] = useState(false);
  const [banReason, setBanReason] = useState('');
  const [banDuration, setBanDuration] = useState<number | undefined>(undefined);

  useEscapeKey(onClose);

  const banMutation = useMutation({
    mutationFn: () => {
      if (!log.client_ip) {
        throw new Error('Missing client IP');
      }
      return banIP({
        ip_address: log.client_ip,
        reason: banReason || `Banned from log viewer - ${log.request_uri || 'N/A'}`,
        ban_time: banDuration,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] });
      alert(t('banIP.success', { ip: log.client_ip }));
      setShowBanForm(false);
      setBanReason('');
      setBanDuration(undefined);
    },
    onError: (error) => {
      alert(t('banIP.failed', { error: (error as Error).message }));
    },
  });

  const disableMutation = useMutation({
    mutationFn: () => {
      if (!log.host || !log.rule_id) {
        throw new Error('Missing host or rule_id');
      }
      return disableWAFRuleByHost({
        host: log.host,
        rule_id: log.rule_id,
        rule_category: log.attack_type,
        rule_description: log.rule_message,
        reason: disableReason || 'Disabled from log viewer',
      });
    },
    onSuccess: () => {
      alert(`Rule ${log.rule_id} has been disabled for ${log.host}`);
      onRuleDisabled?.();
      onClose();
    },
    onError: (error) => {
      alert(`Failed to disable rule: ${(error as Error).message}`);
    },
  });

  const handleDisableRule = () => {
    if (!log.host) {
      alert('Cannot disable rule: Host not available in this log entry.');
      return;
    }
    disableMutation.mutate();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <LogTypeBadge type={log.log_type} />
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('detail.title')}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 overflow-y-auto max-h-[calc(90vh-120px)]">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.timestamp')}</label>
              <p className="text-sm text-slate-900 dark:text-white">{formatTime(log.timestamp)}</p>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.clientIP')}</label>
              <div className="flex items-center gap-2">
                {log.client_ip ? (
                  <button
                    onClick={() => setShowBanForm(!showBanForm)}
                    className="group flex items-center gap-2 px-2 py-1 -ml-2 text-sm font-mono text-slate-900 dark:text-white hover:bg-red-50 dark:hover:bg-red-900/30 hover:text-red-700 dark:hover:text-red-400 rounded-lg transition-colors"
                    title={t('banIP.clickToBan')}
                  >
                    <span>{log.client_ip}</span>
                    <svg className="w-4 h-4 text-red-500 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                    </svg>
                  </button>
                ) : (
                  <p className="text-sm text-slate-900 dark:text-white font-mono">-</p>
                )}
              </div>
            </div>
          </div>

          {/* IP Ban Form */}
          {showBanForm && log.client_ip && (
            <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
              <h4 className="text-sm font-semibold text-red-800 dark:text-red-300 mb-3">{t('banIP.title', { ip: log.client_ip })}</h4>
              <div className="space-y-3">
                <div>
                  <label className="text-xs font-medium text-red-700 dark:text-red-400 uppercase mb-1 block">
                    {t('banIP.reason')}
                  </label>
                  <input
                    type="text"
                    value={banReason}
                    onChange={(e) => setBanReason(e.target.value)}
                    placeholder={t('banIP.reasonPlaceholder')}
                    className="w-full px-3 py-2 border border-red-300 dark:border-red-700 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-red-700 dark:text-red-400 uppercase mb-1 block">
                    {t('banIP.duration')}
                  </label>
                  <select
                    value={banDuration ?? ''}
                    onChange={(e) => setBanDuration(e.target.value ? parseInt(e.target.value) : undefined)}
                    className="w-full px-3 py-2 border border-red-300 dark:border-red-700 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-red-500 bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
                  >
                    <option value="">{t('banIP.permanent')}</option>
                    <option value="3600">{t('banIP.duration1h')}</option>
                    <option value="86400">{t('banIP.duration1d')}</option>
                    <option value="604800">{t('banIP.duration1w')}</option>
                    <option value="2592000">{t('banIP.duration1m')}</option>
                  </select>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => banMutation.mutate()}
                    disabled={banMutation.isPending}
                    className="flex-1 px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {banMutation.isPending ? t('banIP.processing') : t('banIP.submit')}
                  </button>
                  <button
                    onClick={() => {
                      setShowBanForm(false);
                      setBanReason('');
                      setBanDuration(undefined);
                    }}
                    className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
                  >
                    {t('banIP.cancel')}
                  </button>
                </div>
              </div>
            </div>
          )}

          {log.geo_country_code && log.geo_country_code !== '--' && /^[A-Z]{2}$/i.test(log.geo_country_code) && (
            <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-2 block">{t('detail.geoLocation')}</label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div>
                  <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.country')}</span>
                  <p className="text-sm text-slate-900 dark:text-white flex items-center gap-1">
                    <span className="text-base">
                      {log.geo_country_code
                        .toUpperCase()
                        .split('')
                        .map(char => String.fromCodePoint(127397 + char.charCodeAt(0)))
                        .join('')}
                    </span>
                    {log.geo_country || log.geo_country_code}
                  </p>
                </div>
                {log.geo_city && (
                  <div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.city')}</span>
                    <p className="text-sm text-slate-900 dark:text-white">{log.geo_city}</p>
                  </div>
                )}
                {log.geo_asn && (
                  <div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.asn')}</span>
                    <p className="text-sm text-slate-900 dark:text-white font-mono">{log.geo_asn}</p>
                  </div>
                )}
                {log.geo_org && (
                  <div className="col-span-2 md:col-span-1">
                    <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.organization')}</span>
                    <p className="text-sm text-slate-900 dark:text-white truncate" title={log.geo_org}>{log.geo_org}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {log.log_type === 'access' && (
            <>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.method')}</label>
                  <p className="text-sm">{log.request_method && <MethodBadge method={log.request_method} />}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.status')}</label>
                  <p className="text-sm">{log.status_code && <StatusCodeBadge code={log.status_code} />}</p>
                </div>
              </div>
              <div className="mb-4">
                <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.requestURI')}</label>
                <p className="text-sm text-slate-900 dark:text-white font-mono break-all bg-slate-50 dark:bg-slate-700/50 p-2 rounded">
                  {log.request_uri || '-'}
                </p>
              </div>
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.protocol')}</label>
                  <p className="text-sm text-slate-900 dark:text-white">{log.request_protocol || '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.responseSize')}</label>
                  <p className="text-sm text-slate-900 dark:text-white">{log.body_bytes_sent ? formatBytes(log.body_bytes_sent) : '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.requestTime')}</label>
                  <p className="text-sm text-slate-900 dark:text-white">{log.request_time ? `${log.request_time}s` : '-'}</p>
                </div>
              </div>
              {log.http_user_agent && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.userAgent')}</label>
                  <p className="text-sm text-slate-600 dark:text-slate-300 break-all">{log.http_user_agent}</p>
                </div>
              )}
              {log.http_referer && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.referer')}</label>
                  <p className="text-sm text-slate-600 dark:text-slate-300 break-all">{log.http_referer}</p>
                </div>
              )}
            </>
          )}

          {log.log_type === 'error' && (
            <div className="mb-4">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.errorMessage')}</label>
              <p className="text-sm text-red-700 dark:text-red-400 font-mono bg-red-50 dark:bg-red-900/20 p-3 rounded">
                {log.error_message || '-'}
              </p>
            </div>
          )}

          {log.log_type === 'modsec' && (
            <>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.host')}</label>
                  <p className="text-sm text-orange-600 dark:text-orange-400 font-medium">{log.host || '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.action')}</label>
                  <p className="text-sm">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      log.action_taken === 'blocked' ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400' :
                      log.action_taken === 'excluded' ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400' :
                      'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-400'
                    }`}>
                      {log.action_taken === 'excluded' ? 'pass (excluded)' : log.action_taken || 'logged'}
                    </span>
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.ruleId')}</label>
                  <p className="text-sm text-slate-900 dark:text-white font-mono">{log.rule_id || '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.severity')}</label>
                  <p className="text-sm text-slate-900 dark:text-white">{log.rule_severity || '-'}</p>
                </div>
              </div>
              {log.rule_message && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.ruleMessage')}</label>
                  <p className="text-sm text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20 p-3 rounded">{log.rule_message}</p>
                </div>
              )}
              {log.attack_type && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.attackType')}</label>
                  <p className="text-sm text-slate-900 dark:text-white">{log.attack_type}</p>
                </div>
              )}

              {log.rule_id && (
                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
                  {!showDisableForm ? (
                    <button
                      onClick={() => setShowDisableForm(true)}
                      className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20 hover:bg-orange-100 dark:hover:bg-orange-900/30 rounded-lg transition-colors"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                      </svg>
                      {t('disableRule.button')}
                    </button>
                  ) : (
                    <div className="space-y-3">
                      <div>
                        <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-1 block">
                          {t('disableRule.reason')}
                        </label>
                        <input
                          type="text"
                          value={disableReason}
                          onChange={(e) => setDisableReason(e.target.value)}
                          placeholder={t('disableRule.reasonPlaceholder')}
                          className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
                        />
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={handleDisableRule}
                          disabled={disableMutation.isPending}
                          className="flex-1 px-4 py-2 text-sm font-medium text-white bg-orange-600 hover:bg-orange-700 rounded-lg transition-colors disabled:opacity-50"
                        >
                          {disableMutation.isPending ? t('disableRule.processing') : t('disableRule.submit', { ruleId: log.rule_id })}
                        </button>
                        <button
                          onClick={() => setShowDisableForm(false)}
                          className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
                        >
                          {t('disableRule.cancel')}
                        </button>
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400" dangerouslySetInnerHTML={{ __html: t('disableRule.description', { host: log.host, ruleId: log.rule_id }) }} />
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {log.raw_log && (
            <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.rawLog')}</label>
              <pre className="text-xs bg-slate-800 text-slate-200 p-3 rounded mt-1 overflow-x-auto">
                {log.raw_log}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface SettingsModalProps {
  settings: LogSettings;
  onClose: () => void;
}

export function SettingsModal({ settings, onClose }: SettingsModalProps) {
  const queryClient = useQueryClient();
  const [retentionDays, setRetentionDays] = useState(settings.retention_days);
  const [autoCleanup, setAutoCleanup] = useState(settings.auto_cleanup_enabled);

  useEscapeKey(onClose);

  const updateMutation = useMutation({
    mutationFn: updateLogSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['log-settings'] });
      onClose();
    },
  });

  const cleanupMutation = useMutation({
    mutationFn: cleanupLogs,
    onSuccess: (result) => {
      alert(`Cleaned up ${result.deleted} old logs`);
      queryClient.invalidateQueries({ queryKey: ['logs'] });
      queryClient.invalidateQueries({ queryKey: ['log-stats'] });
    },
  });

  const handleSave = () => {
    updateMutation.mutate({
      retention_days: retentionDays,
      auto_cleanup_enabled: autoCleanup,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-md w-full">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Log Settings</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
              Retention Period (days)
            </label>
            <input
              type="number"
              value={retentionDays}
              onChange={(e) => setRetentionDays(parseInt(e.target.value) || 30)}
              min={1}
              max={365}
              className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white"
            />
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Logs older than this will be automatically deleted
            </p>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                Auto Cleanup
              </label>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Automatically delete old logs
              </p>
            </div>
            <button
              type="button"
              onClick={() => setAutoCleanup(!autoCleanup)}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                autoCleanup ? 'bg-primary-600' : 'bg-slate-200 dark:bg-slate-600'
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  autoCleanup ? 'translate-x-6' : 'translate-x-1'
                }`}
              />
            </button>
          </div>

          <div className="pt-4 border-t border-slate-200 dark:border-slate-700">
            <button
              onClick={() => cleanupMutation.mutate()}
              disabled={cleanupMutation.isPending}
              className="w-full py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
            >
              {cleanupMutation.isPending ? 'Cleaning...' : 'Cleanup Old Logs Now'}
            </button>
          </div>
        </div>

        <div className="flex gap-3 p-4 border-t border-slate-200 dark:border-slate-700">
          <button
            onClick={onClose}
            className="flex-1 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            className="flex-1 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors"
          >
            {updateMutation.isPending ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

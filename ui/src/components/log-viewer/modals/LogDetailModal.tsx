import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEscapeKey } from '../../../hooks/useEscapeKey';
import { disableWAFRuleByHost, disableGlobalWAFRule } from '../../../api/waf';
import { banIP, addURIBlockRule } from '../../../api/security';
import { api } from '../../../api/client';
import type { Log } from '../../../types/log';
import type { URIMatchType } from '../../../types/security';
import { formatBytes } from '../utils';
import { StatusCodeBadge, LogTypeBadge, MethodBadge } from '../badges';
import { RelatedLogsModal } from './RelatedLogsModal';

interface LogDetailModalProps {
  log: Log;
  onClose: () => void;
  onRuleDisabled?: () => void;
}

export function LogDetailModal({ log, onClose, onRuleDisabled }: LogDetailModalProps) {
  const { t, i18n } = useTranslation('logs');
  const queryClient = useQueryClient();
  const [showRelatedLogs, setShowRelatedLogs] = useState(false);
  const [disableReason, setDisableReason] = useState('');
  const [showDisableForm, setShowDisableForm] = useState(false);
  const [isGlobalDisable, setIsGlobalDisable] = useState(false);
  const [showBanForm, setShowBanForm] = useState(false);
  const [banReason, setBanReason] = useState('');
  const [banDuration, setBanDuration] = useState<number | undefined>(undefined);
  const [isGlobalBan, setIsGlobalBan] = useState(false);

  useEscapeKey(onClose);

  const [showBlockURIForm, setShowBlockURIForm] = useState(false);
  const [uriMatchType, setURIMatchType] = useState<URIMatchType>('exact');
  const [uriDescription, setURIDescription] = useState('');
  const [proxyHostId, setProxyHostId] = useState<string | null>(null);

  // Fetch proxy host ID for the current host
  const { data: hostData } = useQuery({
    queryKey: ['proxyHostByDomain', log.host],
    queryFn: async () => {
      if (!log.host) return null;
      const response = await api.get<{ id: string }>(`/api/v1/proxy-hosts/by-domain/${encodeURIComponent(log.host)}`);
      return response.id || null;
    },
    enabled: !!log.host && (showBlockURIForm || showBanForm),
    staleTime: 60000,
  });

  // Update proxyHostId when data is fetched
  React.useEffect(() => {
    if (hostData) {
      setProxyHostId(hostData);
    }
  }, [hostData]);

  const banMutation = useMutation({
    mutationFn: () => {
      if (!log.client_ip) {
        throw new Error('Missing client IP');
      }
      const banData: { ip_address: string; reason?: string; ban_time?: number; proxy_host_id?: string } = {
        ip_address: log.client_ip,
        reason: banReason || `Banned from log viewer - ${log.request_uri || 'N/A'}`,
        ban_time: banDuration,
      };
      // Only add proxy_host_id if it's a per-host ban (not global)
      if (!isGlobalBan && proxyHostId) {
        banData.proxy_host_id = proxyHostId;
      }
      return banIP(banData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['banned-ips'] });
      alert(isGlobalBan
        ? t('banIP.successGlobal', { ip: log.client_ip, defaultValue: '{{ip}}가 전역 차단되었습니다.' })
        : t('banIP.success', { ip: log.client_ip }));
      setShowBanForm(false);
      setBanReason('');
      setBanDuration(undefined);
      setIsGlobalBan(false);
    },
    onError: (error) => {
      alert(t('banIP.failed', { error: (error as Error).message }));
    },
  });

  const blockURIMutation = useMutation({
    mutationFn: () => {
      if (!proxyHostId) {
        throw new Error('Missing proxy host ID');
      }
      if (!log.request_uri) {
        throw new Error('Missing URI');
      }
      return addURIBlockRule(proxyHostId, {
        pattern: log.request_uri,
        match_type: uriMatchType,
        description: uriDescription || `Blocked from log viewer`,
        enabled: true,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['uriBlock', proxyHostId] });
      alert(t('blockURI.success', { uri: log.request_uri }));
      setShowBlockURIForm(false);
      setURIDescription('');
      setURIMatchType('exact');
    },
    onError: (error) => {
      alert(t('blockURI.failed', { error: (error as Error).message }));
    },
  });

  const disableMutation = useMutation({
    mutationFn: async () => {
      if (!log.rule_id) {
        throw new Error('Missing rule_id');
      }
      if (isGlobalDisable) {
        // Global disable - applies to all hosts
        await disableGlobalWAFRule(log.rule_id, {
          rule_id: log.rule_id,
          rule_category: log.attack_type,
          rule_description: log.rule_message,
          reason: disableReason || t('messages.disabledReasonDefault'),
        });
      } else {
        // Per-host disable
        if (!log.host) {
          throw new Error('Missing host');
        }
        await disableWAFRuleByHost({
          host: log.host,
          rule_id: log.rule_id,
          rule_category: log.attack_type,
          rule_description: log.rule_message,
          reason: disableReason || t('messages.disabledReasonDefault'),
        });
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['global-waf-rules'] });
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] });
      queryClient.invalidateQueries({ queryKey: ['waf-hosts'] });
      alert(isGlobalDisable
        ? t('messages.ruleDisabledGlobal', { ruleId: log.rule_id, defaultValue: '규칙 {{ruleId}}가 전역 비활성화되었습니다.' })
        : t('messages.ruleDisabled', { ruleId: log.rule_id, host: log.host }));
      onRuleDisabled?.();
      setShowDisableForm(false);
      setDisableReason('');
      setIsGlobalDisable(false);
    },
    onError: (error) => {
      alert(t('messages.ruleDisableFailed', { error: (error as Error).message }));
    },
  });

  const handleDisableRule = () => {
    if (!isGlobalDisable && !log.host) {
      alert(t('messages.cannotDisable'));
      return;
    }
    disableMutation.mutate();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col">
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
              <p className="text-sm text-slate-900 dark:text-white">{new Date(log.timestamp).toLocaleString(i18n.language)}</p>
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
                {/* Scope Toggle */}
                <div>
                  <label className="text-xs font-medium text-red-700 dark:text-red-400 uppercase mb-2 block">
                    {t('banIP.scope', { defaultValue: '적용 범위' })}
                  </label>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => setIsGlobalBan(false)}
                      className={`flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                        !isGlobalBan
                          ? 'bg-red-600 text-white'
                          : 'bg-white dark:bg-slate-800 text-red-700 dark:text-red-400 border border-red-300 dark:border-red-700 hover:bg-red-50 dark:hover:bg-red-900/30'
                      }`}
                    >
                      {t('banIP.perHost', { defaultValue: '이 호스트만', host: log.host })}
                    </button>
                    <button
                      type="button"
                      onClick={() => setIsGlobalBan(true)}
                      className={`flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                        isGlobalBan
                          ? 'bg-purple-600 text-white'
                          : 'bg-white dark:bg-slate-800 text-purple-700 dark:text-purple-400 border border-purple-300 dark:border-purple-700 hover:bg-purple-50 dark:hover:bg-purple-900/30'
                      }`}
                    >
                      {t('banIP.global', { defaultValue: '전역 차단 (모든 호스트)' })}
                    </button>
                  </div>
                  {isGlobalBan && (
                    <p className="mt-1 text-xs text-purple-600 dark:text-purple-400">
                      {t('banIP.globalDescription', { defaultValue: '이 IP는 모든 프록시 호스트에서 차단됩니다.' })}
                    </p>
                  )}
                </div>
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
                    className={`flex-1 px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 ${
                      isGlobalBan ? 'bg-purple-600 hover:bg-purple-700' : 'bg-red-600 hover:bg-red-700'
                    }`}
                  >
                    {banMutation.isPending ? t('banIP.processing') : (isGlobalBan ? t('banIP.submitGlobal', { defaultValue: '전역 차단' }) : t('banIP.submit'))}
                  </button>
                  <button
                    onClick={() => {
                      setShowBanForm(false);
                      setBanReason('');
                      setBanDuration(undefined);
                      setIsGlobalBan(false);
                    }}
                    className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
                  >
                    {t('banIP.cancel')}
                  </button>
                </div>
              </div>
            </div>
          )}

          {log.geo_country_code && (
            <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
              <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-2 block">{t('detail.geoIp')}</label>
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
                    <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.org')}</span>
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
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.method')}</label>
                  <p className="text-sm">{log.request_method && <MethodBadge method={log.request_method} />}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.status')}</label>
                  <p className="text-sm">{log.status_code && <StatusCodeBadge code={log.status_code} />}</p>
                </div>
              </div>
              <div className="mb-4">
                <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.uri')}</label>
                <div className="bg-slate-50 dark:bg-slate-800 p-2 rounded">
                  {log.request_uri ? (
                    <button
                      onClick={() => setShowBlockURIForm(!showBlockURIForm)}
                      className="group text-sm text-slate-900 dark:text-slate-200 font-mono break-all text-left hover:text-purple-700 dark:hover:text-purple-400 transition-colors"
                      title={t('blockURI.clickToBlock')}
                    >
                      <span className="flex items-center gap-2">
                        <span className="break-all">{log.request_uri}</span>
                        <svg className="w-4 h-4 flex-shrink-0 text-purple-500 opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                        </svg>
                      </span>
                    </button>
                  ) : (
                    <span className="text-sm text-slate-900 dark:text-slate-200 font-mono">-</span>
                  )}
                </div>
              </div>

              {/* URI Block Form */}
              {showBlockURIForm && log.request_uri && (
                <div className="mb-4 p-4 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg">
                  <h4 className="text-sm font-semibold text-purple-800 dark:text-purple-300 mb-3">{t('blockURI.title')}</h4>
                  {!proxyHostId && log.host && (
                    <p className="text-xs text-purple-600 dark:text-purple-400 mb-2">{t('blockURI.loadingHost')}</p>
                  )}
                  <div className="space-y-3">
                    <div>
                      <label className="text-xs font-medium text-purple-700 dark:text-purple-400 uppercase mb-1 block">
                        {t('blockURI.pattern')}
                      </label>
                      <p className="px-3 py-2 border border-purple-300 dark:border-purple-700 rounded-lg text-sm font-mono bg-white dark:bg-slate-800 text-slate-900 dark:text-white break-all">
                        {log.request_uri}
                      </p>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-purple-700 dark:text-purple-400 uppercase mb-1 block">
                        {t('blockURI.matchType')}
                      </label>
                      <select
                        value={uriMatchType}
                        onChange={(e) => setURIMatchType(e.target.value as URIMatchType)}
                        className="w-full px-3 py-2 border border-purple-300 dark:border-purple-700 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500 bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
                      >
                        <option value="exact">{t('blockURI.matchTypes.exact')}</option>
                        <option value="prefix">{t('blockURI.matchTypes.prefix')}</option>
                        <option value="regex">{t('blockURI.matchTypes.regex')}</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-purple-700 dark:text-purple-400 uppercase mb-1 block">
                        {t('blockURI.description')}
                      </label>
                      <input
                        type="text"
                        value={uriDescription}
                        onChange={(e) => setURIDescription(e.target.value)}
                        placeholder={t('blockURI.descriptionPlaceholder')}
                        className="w-full px-3 py-2 border border-purple-300 dark:border-purple-700 rounded-lg text-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500 bg-white dark:bg-slate-800 text-slate-900 dark:text-white"
                      />
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => blockURIMutation.mutate()}
                        disabled={blockURIMutation.isPending || !proxyHostId}
                        className="flex-1 px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors disabled:opacity-50"
                      >
                        {blockURIMutation.isPending ? t('blockURI.processing') : t('blockURI.submit')}
                      </button>
                      <button
                        onClick={() => {
                          setShowBlockURIForm(false);
                          setURIDescription('');
                          setURIMatchType('exact');
                        }}
                        className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
                      >
                        {t('blockURI.cancel')}
                      </button>
                    </div>
                  </div>
                </div>
              )}
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.protocol')}</label>
                  <p className="text-sm text-slate-900">{log.request_protocol || '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.responseSize')}</label>
                  <p className="text-sm text-slate-900">{log.body_bytes_sent ? formatBytes(log.body_bytes_sent) : '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.requestTime')}</label>
                  <p className="text-sm text-slate-900">{log.request_time ? `${log.request_time}s` : '-'}</p>
                </div>
              </div>
              {log.http_user_agent && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.userAgent')}</label>
                  <p className="text-sm text-slate-600 break-all">{log.http_user_agent}</p>
                </div>
              )}
              {log.http_referer && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.referer')}</label>
                  <p className="text-sm text-slate-600 break-all">{log.http_referer}</p>
                </div>
              )}
            </>
          )}

          {log.log_type === 'error' && (
            <div className="mb-4">
              <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.errorMsg')}</label>
              <p className="text-sm text-red-700 dark:text-red-400 font-mono bg-red-50 dark:bg-red-900/30 p-3 rounded">
                {log.error_message || '-'}
              </p>
            </div>
          )}

          {log.log_type === 'modsec' && (
            <>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.host')}</label>
                  <p className="text-sm text-orange-600 font-medium">{log.host || '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.action')}</label>
                  <p className="text-sm">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${log.action_taken === 'blocked' ? 'bg-red-100 text-red-800' :
                      log.action_taken === 'excluded' ? 'bg-green-100 text-green-800' :
                        'bg-yellow-100 text-yellow-800'
                      }`}>
                      {log.action_taken === 'excluded' ? t('table.logType.pass') : log.action_taken || t('table.logType.logged')}
                    </span>
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.ruleId')}</label>
                  <p className="text-sm text-slate-900 dark:text-slate-200 font-mono">{log.rule_id || '-'}</p>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.severity')}</label>
                  <p className="text-sm text-slate-900 dark:text-slate-200">{log.rule_severity || '-'}</p>
                </div>
              </div>
              {log.rule_message && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.ruleMsg')}</label>
                  <p className="text-sm text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/30 p-3 rounded">{log.rule_message}</p>
                </div>
              )}
              {log.attack_type && (
                <div className="mb-4">
                  <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.attackType')}</label>
                  <p className="text-sm text-slate-900 dark:text-slate-200">{log.attack_type}</p>
                </div>
              )}

              {log.rule_id && (
                <div className="mt-4 pt-4 border-t border-slate-200">
                  {!showDisableForm ? (
                    <button
                      onClick={() => setShowDisableForm(true)}
                      className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/30 hover:bg-orange-100 dark:hover:bg-orange-900/50 rounded-lg transition-colors"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                      </svg>
                      {t('disableRule.button')}
                    </button>
                  ) : (
                    <div className="space-y-3">
                      {/* Scope Toggle */}
                      <div>
                        <label className="text-xs font-medium text-slate-500 uppercase mb-1 block">
                          {t('disableRule.scope', { defaultValue: '비활성화 범위' })}
                        </label>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => setIsGlobalDisable(false)}
                            className={`flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                              !isGlobalDisable
                                ? 'bg-orange-600 text-white'
                                : 'bg-white dark:bg-slate-800 text-orange-700 dark:text-orange-400 border border-orange-300 dark:border-orange-700 hover:bg-orange-50 dark:hover:bg-orange-900/30'
                            }`}
                          >
                            {t('disableRule.perHost', { defaultValue: '이 호스트만' })}
                          </button>
                          <button
                            type="button"
                            onClick={() => setIsGlobalDisable(true)}
                            className={`flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                              isGlobalDisable
                                ? 'bg-purple-600 text-white'
                                : 'bg-white dark:bg-slate-800 text-purple-700 dark:text-purple-400 border border-purple-300 dark:border-purple-700 hover:bg-purple-50 dark:hover:bg-purple-900/30'
                            }`}
                          >
                            {t('disableRule.global', { defaultValue: '전역 비활성화 (모든 호스트)' })}
                          </button>
                        </div>
                        {isGlobalDisable && (
                          <p className="mt-1 text-xs text-purple-600 dark:text-purple-400">
                            {t('disableRule.globalDescription', { defaultValue: '이 정책은 모든 프록시 호스트에서 비활성화됩니다.' })}
                          </p>
                        )}
                      </div>
                      <div>
                        <label className="text-xs font-medium text-slate-500 uppercase mb-1 block">
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
                          className={`flex-1 px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 ${
                            isGlobalDisable ? 'bg-purple-600 hover:bg-purple-700' : 'bg-orange-600 hover:bg-orange-700'
                          }`}
                        >
                          {disableMutation.isPending
                            ? t('disableRule.processing')
                            : (isGlobalDisable
                              ? t('disableRule.submitGlobal', { ruleId: log.rule_id, defaultValue: '전역 비활성화' })
                              : t('disableRule.submit', { ruleId: log.rule_id }))}
                        </button>
                        <button
                          onClick={() => setShowDisableForm(false)}
                          className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
                        >
                          {t('disableRule.cancel')}
                        </button>
                      </div>
                      <p className="text-xs text-slate-500">
                        {isGlobalDisable
                          ? <span>{t('disableRule.globalNote', { ruleId: log.rule_id, defaultValue: `정책 ${log.rule_id}이(가) 모든 호스트에서 비활성화됩니다.` })}</span>
                          : <span dangerouslySetInnerHTML={{ __html: t('disableRule.description', { ruleId: log.rule_id, host: log.host, interpolation: { escapeValue: false } }) }} />
                        }
                      </p>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {log.log_type === 'modsec' && (
            <div className="mt-4 pt-4 border-t border-slate-200">
              <button
                onClick={() => setShowRelatedLogs(true)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors border border-slate-300 dark:border-slate-600"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                {t('detail.viewAccessLog')}
              </button>
            </div>
          )}

          {showRelatedLogs && (
            <RelatedLogsModal
              clientIp={log.client_ip}
              requestUri={log.request_uri}
              timestamp={log.timestamp.toString()}
              host={log.host}
              userAgent={log.http_user_agent}
              onClose={() => setShowRelatedLogs(false)}
            />
          )}

          {log.raw_log && (
            <div className="mt-4 pt-4 border-t border-slate-200">
              <label className="text-xs font-medium text-slate-500 uppercase">{t('detail.rawLog')}</label>
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

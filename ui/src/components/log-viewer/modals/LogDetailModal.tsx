import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEscapeKey } from '../../../hooks/useEscapeKey';
import { disableWAFRuleByHost, disableGlobalWAFRule } from '../../../api/waf';
import { banIP, addURIBlockRule } from '../../../api/security';
import { api } from '../../../api/client';
import type { Log } from '../../../types/log';
import type { URIMatchType } from '../../../types/security';
import { RelatedLogsModal } from './RelatedLogsModal';
import { LogDetailHeader, LogDetailGeoIP } from './LogDetailHeader';
import {
  BanIPForm,
  BlockURIForm,
  DisableRuleForm,
  AccessLogBody,
  ModsecLogBody,
} from './LogDetailBody';
import {
  LogRawBlock,
  ErrorMessageBlock,
  ViewAccessLogButton,
  URIRow,
} from './LogRawBlock';

interface LogDetailModalProps {
  log: Log;
  onClose: () => void;
  onRuleDisabled?: () => void;
}

export function LogDetailModal({ log, onClose, onRuleDisabled }: LogDetailModalProps) {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const [showRelatedLogs, setShowRelatedLogs] = useState(false);
  const [disableReason, setDisableReason] = useState('');
  const [showDisableForm, setShowDisableForm] = useState(false);
  const [isGlobalDisable, setIsGlobalDisable] = useState(!log.host);
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
      setIsGlobalDisable(!log.host);
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
        <LogDetailHeader log={log} onClose={onClose} onBanClick={() => setShowBanForm(!showBanForm)} />

        <div className="p-4 overflow-y-auto max-h-[calc(90vh-120px)]">
          {/* IP Ban Form */}
          {showBanForm && log.client_ip && (
            <BanIPForm
              log={log}
              banReason={banReason}
              setBanReason={setBanReason}
              banDuration={banDuration}
              setBanDuration={setBanDuration}
              isGlobalBan={isGlobalBan}
              setIsGlobalBan={setIsGlobalBan}
              onSubmit={() => banMutation.mutate()}
              onCancel={() => {
                setShowBanForm(false);
                setBanReason('');
                setBanDuration(undefined);
                setIsGlobalBan(false);
              }}
              isPending={banMutation.isPending}
            />
          )}

          <LogDetailGeoIP log={log} />

          {log.log_type === 'access' && (
            <>
              <URIRow log={log} showBlockURIForm={showBlockURIForm} onToggleBlockForm={() => setShowBlockURIForm(!showBlockURIForm)} />

              {/* URI Block Form */}
              {showBlockURIForm && log.request_uri && (
                <BlockURIForm
                  log={log}
                  uriMatchType={uriMatchType}
                  setURIMatchType={setURIMatchType}
                  uriDescription={uriDescription}
                  setURIDescription={setURIDescription}
                  proxyHostId={proxyHostId}
                  onSubmit={() => blockURIMutation.mutate()}
                  onCancel={() => {
                    setShowBlockURIForm(false);
                    setURIDescription('');
                    setURIMatchType('exact');
                  }}
                  isPending={blockURIMutation.isPending}
                />
              )}

              <AccessLogBody log={log} />
            </>
          )}

          {log.log_type === 'error' && <ErrorMessageBlock errorMessage={log.error_message} />}

          {log.log_type === 'modsec' && (
            <>
              <ModsecLogBody log={log} />
              {log.rule_id && (
                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
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
                    <DisableRuleForm
                      log={log}
                      disableReason={disableReason}
                      setDisableReason={setDisableReason}
                      isGlobalDisable={isGlobalDisable}
                      setIsGlobalDisable={setIsGlobalDisable}
                      onSubmit={handleDisableRule}
                      onCancel={() => setShowDisableForm(false)}
                      isPending={disableMutation.isPending}
                    />
                  )}
                </div>
              )}
            </>
          )}

          {log.log_type === 'modsec' && <ViewAccessLogButton onClick={() => setShowRelatedLogs(true)} />}

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

          <LogRawBlock rawLog={log.raw_log} />
        </div>
      </div>
    </div>
  );
}

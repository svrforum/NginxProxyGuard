import { useTranslation } from 'react-i18next';
import type { Log } from '../../../types/log';
import type { URIMatchType } from '../../../types/security';
import { formatBytes } from '../utils';
import { StatusCodeBadge, MethodBadge } from '../badges';

// IP Ban Form
interface BanIPFormProps {
  log: Log;
  banReason: string;
  setBanReason: (v: string) => void;
  banDuration: number | undefined;
  setBanDuration: (v: number | undefined) => void;
  isGlobalBan: boolean;
  setIsGlobalBan: (v: boolean) => void;
  onSubmit: () => void;
  onCancel: () => void;
  isPending: boolean;
}

export function BanIPForm({
  log, banReason, setBanReason, banDuration, setBanDuration, isGlobalBan, setIsGlobalBan, onSubmit, onCancel, isPending,
}: BanIPFormProps) {
  const { t } = useTranslation('logs');
  return (
    <div className="mb-4 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
      <h4 className="text-sm font-semibold text-red-800 dark:text-red-300 mb-3">{t('banIP.title', { ip: log.client_ip })}</h4>
      <div className="space-y-3">
        {/* Scope Toggle */}
        <div>
          <label className="text-xs font-medium text-red-700 dark:text-red-400 uppercase mb-2 block">
            {t('banIP.scope')}
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
              {t('banIP.perHost')}
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
              {t('banIP.global')}
            </button>
          </div>
          {isGlobalBan && (
            <p className="mt-1 text-xs text-purple-600 dark:text-purple-400">
              {t('banIP.globalDescription')}
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
            onClick={onSubmit}
            disabled={isPending}
            className={`flex-1 px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 ${
              isGlobalBan ? 'bg-purple-600 hover:bg-purple-700' : 'bg-red-600 hover:bg-red-700'
            }`}
          >
            {isPending ? t('banIP.processing') : (isGlobalBan ? t('banIP.submitGlobal') : t('banIP.submit'))}
          </button>
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
          >
            {t('banIP.cancel')}
          </button>
        </div>
      </div>
    </div>
  );
}

// URI Block Form
interface BlockURIFormProps {
  log: Log;
  uriMatchType: URIMatchType;
  setURIMatchType: (t: URIMatchType) => void;
  uriDescription: string;
  setURIDescription: (d: string) => void;
  proxyHostId: string | null;
  onSubmit: () => void;
  onCancel: () => void;
  isPending: boolean;
}

export function BlockURIForm({
  log, uriMatchType, setURIMatchType, uriDescription, setURIDescription, proxyHostId, onSubmit, onCancel, isPending,
}: BlockURIFormProps) {
  const { t } = useTranslation('logs');
  return (
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
            onClick={onSubmit}
            disabled={isPending || !proxyHostId}
            className="flex-1 px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors disabled:opacity-50"
          >
            {isPending ? t('blockURI.processing') : t('blockURI.submit')}
          </button>
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
          >
            {t('blockURI.cancel')}
          </button>
        </div>
      </div>
    </div>
  );
}

// Disable Rule Form
interface DisableRuleFormProps {
  log: Log;
  disableReason: string;
  setDisableReason: (r: string) => void;
  isGlobalDisable: boolean;
  setIsGlobalDisable: (v: boolean) => void;
  onSubmit: () => void;
  onCancel: () => void;
  isPending: boolean;
}

export function DisableRuleForm({
  log, disableReason, setDisableReason, isGlobalDisable, setIsGlobalDisable, onSubmit, onCancel, isPending,
}: DisableRuleFormProps) {
  const { t } = useTranslation('logs');
  const descriptionHtml = t('disableRule.description', { ruleId: log.rule_id, host: log.host, interpolation: { escapeValue: false } });
  return (
    <div className="space-y-3">
      {/* Scope Toggle */}
      <div>
        <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-1 block">
          {t('disableRule.scope', { defaultValue: '비활성화 범위' })}
        </label>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setIsGlobalDisable(false)}
            disabled={!log.host}
            title={!log.host ? t('disableRule.perHostUnavailable', { defaultValue: '호스트 정보가 없어 전역 비활성화만 가능합니다' }) : undefined}
            className={`flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
              !log.host
                ? 'opacity-50 cursor-not-allowed bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500 border border-slate-200 dark:border-slate-700'
                : !isGlobalDisable
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
            {!log.host
              ? t('disableRule.noHostInfo', { defaultValue: '호스트 정보가 없는 로그입니다. 전역 비활성화만 가능합니다.' })
              : t('disableRule.globalDescription', { defaultValue: '이 정책은 모든 프록시 호스트에서 비활성화됩니다.' })}
          </p>
        )}
      </div>
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
          onClick={onSubmit}
          disabled={isPending}
          className={`flex-1 px-4 py-2 text-sm font-medium text-white rounded-lg transition-colors disabled:opacity-50 ${
            isGlobalDisable ? 'bg-purple-600 hover:bg-purple-700' : 'bg-orange-600 hover:bg-orange-700'
          }`}
        >
          {isPending
            ? t('disableRule.processing')
            : (isGlobalDisable
              ? t('disableRule.submitGlobal', { ruleId: log.rule_id, defaultValue: '전역 비활성화' })
              : t('disableRule.submit', { ruleId: log.rule_id }))}
        </button>
        <button
          onClick={onCancel}
          className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 rounded-lg transition-colors"
        >
          {t('disableRule.cancel')}
        </button>
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400">
        {isGlobalDisable
          ? <span>{t('disableRule.globalNote', { ruleId: log.rule_id, defaultValue: `정책 ${log.rule_id}이(가) 모든 호스트에서 비활성화됩니다.` })}</span>
          // eslint-disable-next-line react/no-danger
          : <span dangerouslySetInnerHTML={{ __html: descriptionHtml }} />
        }
      </p>
    </div>
  );
}

// Access-log specific body
export function AccessLogBody({ log }: { log: Log }) {
  const { t } = useTranslation('logs');
  const addrParts = (log.upstream_addr || '').split(',').map((p) => p.trim()).filter(Boolean);
  const statusParts = (log.upstream_status || '').split(',').map((p) => p.trim()).filter(Boolean);
  const attempts = addrParts.map((addr, idx) => ({ addr, status: statusParts[idx] || '-' }));
  const final = attempts[attempts.length - 1];
  const hasRetries = attempts.length > 1;

  return (
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
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div className="min-w-0">
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.protocol')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200 truncate" title={log.request_protocol || '-'}>{log.request_protocol || '-'}</p>
        </div>
        <div className="min-w-0">
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.responseSize')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">{log.body_bytes_sent ? formatBytes(log.body_bytes_sent) : '-'}</p>
        </div>
        <div className="min-w-0">
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.requestTime')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">{log.request_time ? `${log.request_time}s` : '-'}</p>
        </div>
      </div>
      {addrParts.length > 0 && (
        <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase block">{t('detail.upstream')}</label>
            {hasRetries && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400 text-[11px] font-medium">
                ↻ {t('detail.upstreamRetryCount', { count: attempts.length - 1 })}
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.upstreamFinal')}</span>
              <p className="text-sm text-slate-900 dark:text-white font-mono truncate" title={final.addr}>{final.addr}</p>
            </div>
            <div>
              <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.status')}</span>
              <p className="text-sm text-slate-900 dark:text-white font-mono">{final.status}</p>
            </div>
          </div>
          {hasRetries && (
            <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-700/60">
              <span className="text-xs text-slate-500 dark:text-slate-400 block mb-1">{t('detail.upstreamPath')}</span>
              <ol className="space-y-1 text-xs font-mono text-slate-700 dark:text-slate-300">
                {attempts.map((attempt, idx) => (
                  <li key={idx} className="flex items-center gap-2">
                    <span className="text-slate-400 dark:text-slate-500 min-w-[1.5rem]">{idx + 1}.</span>
                    <span>{attempt.addr}</span>
                    <span className="text-slate-400 dark:text-slate-500">→</span>
                    <span>{attempt.status}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
      <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
        <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-2 block">{t('detail.clientInfo')}</label>
        <div className="space-y-2">
          <div>
            <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.userAgent')}</span>
            <p className="text-sm text-slate-900 dark:text-white break-all">{log.http_user_agent || '-'}</p>
          </div>
          <div>
            <span className="text-xs text-slate-500 dark:text-slate-400">{t('detail.referer')}</span>
            <p className="text-sm text-slate-900 dark:text-white break-all">{log.http_referer || '-'}</p>
          </div>
        </div>
      </div>
    </>
  );
}

// ModSec-log specific body (identifying fields)
export function ModsecLogBody({ log }: { log: Log }) {
  const { t } = useTranslation('logs');
  return (
    <>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.host')}</label>
          <p className="text-sm text-orange-600 dark:text-orange-400 font-medium">{log.host || '-'}</p>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.action')}</label>
          <p className="text-sm">
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${log.action_taken === 'blocked' ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300' :
              log.action_taken === 'excluded' ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' :
                'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300'
              }`}>
              {log.action_taken === 'excluded' ? t('table.logType.pass') : log.action_taken || t('table.logType.logged')}
            </span>
          </p>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.ruleId')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200 font-mono">{log.rule_id || '-'}</p>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.severity')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">{log.rule_severity || '-'}</p>
        </div>
      </div>
      {log.rule_message && (
        <div className="mb-4">
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.ruleMsg')}</label>
          <p className="text-sm text-orange-700 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/30 p-3 rounded">{log.rule_message}</p>
        </div>
      )}
      {log.attack_type && (
        <div className="mb-4">
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.attackType')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">{log.attack_type}</p>
        </div>
      )}
    </>
  );
}

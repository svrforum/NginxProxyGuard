import { useTranslation } from 'react-i18next';
import type { Log } from '../../../types/log';
import { formatBytes } from '../utils';
import { StatusCodeBadge } from '../badges';

// The values nginx's stream $status takes. Same numbers as HTTP, different
// meanings, so each gets a line of its own.
const STREAM_STATUSES = new Set([200, 400, 403, 500, 502, 503]);

// Stream-log body: one TCP/UDP connection to a stream host (#392). The host
// and port sit in the header; there is no URI, user agent or block reason.
export function StreamLogBody({ log }: { log: Log }) {
  const { t } = useTranslation('logs');
  const protocol = log.request_protocol || log.request_method;
  const code = log.status_code;
  const upstreams = (log.upstream_addr || '').split(',').map((p) => p.trim()).filter(Boolean);

  return (
    <>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.protocol')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">
            {protocol ? (
              <span className="px-2 py-0.5 rounded text-xs font-medium font-mono bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300">
                {protocol}
              </span>
            ) : (
              '-'
            )}
          </p>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.status')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200 flex flex-wrap items-center gap-2">
            {code != null ? <StatusCodeBadge code={code} /> : '-'}
            {code != null && STREAM_STATUSES.has(code) && (
              <span className="text-xs text-slate-500 dark:text-slate-400">{t(`detail.streamStatus.${code}`)}</span>
            )}
          </p>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.sentBytes')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">
            {log.body_bytes_sent != null ? formatBytes(log.body_bytes_sent) : '-'}
          </p>
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">{t('detail.duration')}</label>
          <p className="text-sm text-slate-900 dark:text-slate-200">
            {log.request_time != null ? `${log.request_time.toFixed(3)}s` : '-'}
          </p>
        </div>
      </div>
      <div className="mb-4 p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
        <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase mb-2 block">{t('detail.upstream')}</label>
        {upstreams.length > 1 ? (
          // nginx tried more than one backend; the last one is where the session ended.
          <ol className="space-y-1 text-xs font-mono text-slate-700 dark:text-slate-300">
            {upstreams.map((addr, idx) => (
              <li key={idx} className="flex items-center gap-2">
                <span className="text-slate-400 dark:text-slate-500 min-w-[1.5rem]">{idx + 1}.</span>
                <span className="break-all">{addr}</span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-slate-900 dark:text-white font-mono break-all">{upstreams[0] || '-'}</p>
        )}
      </div>
    </>
  );
}

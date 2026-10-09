import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { getLogFiles } from '../api/settings';
import RawLogSettingsCard from './raw-log-files/RawLogSettingsCard';
import RawLogFileList from './raw-log-files/RawLogFileList';
import RawLogArchiveCard from './raw-log-files/RawLogArchiveCard';
import type { LogFileLocation } from '../types/settings';
import { RAW_LOG_PAGE_SIZE, type RawLogMessage } from './raw-log-files/shared';

/** Logs -> Raw log files: rotation settings and the files on disk. */
export default function RawLogFiles() {
  const { t } = useTranslation('logs');
  const [message, setMessage] = useState<RawLogMessage | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showMessage = useCallback((m: RawLogMessage) => {
    setMessage(m);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setMessage(null), 5000);
  }, []);
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const [location, setLocation] = useState<LogFileLocation>('local');
  const [page, setPage] = useState(0);
  const { data: logFilesData, error, refetch } = useQuery({
    queryKey: ['logFiles', location, page],
    queryFn: () => getLogFiles({ location, limit: RAW_LOG_PAGE_SIZE, offset: page * RAW_LOG_PAGE_SIZE }),
    placeholderData: keepPreviousData,
    retry: location === 'local' ? 1 : false,
  });
  const changeLocation = (next: LogFileLocation) => {
    setLocation(next);
    setPage(0);
  };

  // A deletion or a retention change can leave the page past the end.
  const total = logFilesData?.total_count ?? 0;
  useEffect(() => {
    if (page > 0 && page * RAW_LOG_PAGE_SIZE >= total && logFilesData) setPage(Math.max(0, Math.ceil(total / RAW_LOG_PAGE_SIZE) - 1));
  }, [page, total, logFilesData]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-800 dark:text-slate-200">{t('rawFiles.title')}</h1>
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{t('rawFiles.subtitle')}</p>
      </div>

      {message && (
        <div
          role="status"
          className={`px-4 py-3 rounded-lg text-sm font-medium ${message.type === 'success'
            ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-800'
            : message.type === 'info'
              ? 'bg-slate-50 dark:bg-slate-700/40 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-600'
              : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-800'
            }`}
        >
          {message.text}
        </div>
      )}

      <RawLogSettingsCard usage={logFilesData?.usage} onMessage={showMessage} />
      {logFilesData?.archive && (
        <RawLogArchiveCard archive={logFilesData.archive} usage={logFilesData.usage} onMessage={showMessage} />
      )}
      <RawLogFileList
        data={logFilesData}
        error={error}
        location={location}
        onLocationChange={changeLocation}
        page={page}
        onPageChange={setPage}
        onRefresh={() => refetch()}
        onMessage={showMessage}
      />
    </div>
  );
}

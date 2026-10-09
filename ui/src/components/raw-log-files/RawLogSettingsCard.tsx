import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getSystemSettings, updateSystemSettings } from '../../api/settings';
import type { SystemSettings, UpdateSystemSettingsRequest } from '../../types/settings';
import { usePermissions } from '../../hooks/usePermissions';
import type { RawLogUsage } from '../../types/rawLogFiles';
import RawLogUsageEstimate from './RawLogUsageEstimate';
import { RAW_LOG_LIMITS, inRawLogRange, type RawLogLimitedField, type RawLogMessage } from './shared';

interface RawLogSettingsCardProps {
  /** Disk use measured by the server (GET /log-files), for the estimate. */
  usage: RawLogUsage | undefined;
  onMessage: (message: RawLogMessage) => void;
}

const inputClass =
  'w-32 px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 bg-white dark:bg-slate-700 text-slate-900 dark:text-white';

/**
 * Rotation settings for the raw nginx log files: the size that triggers an
 * early cut, the retention in days and compression. The rotated-file count is
 * gone from the form — retention is by age now, and the count is a
 * server-side safety cap the operator never sets.
 */
export default function RawLogSettingsCard({ usage, onMessage }: RawLogSettingsCardProps) {
  const { t } = useTranslation('logs');
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can('settings:write');
  const [edited, setEdited] = useState<UpdateSystemSettingsRequest>({});

  const { data: settings } = useQuery({
    queryKey: ['systemSettings'],
    queryFn: getSystemSettings,
  });

  const updateMutation = useMutation({
    mutationFn: updateSystemSettings,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['systemSettings'] });
      queryClient.invalidateQueries({ queryKey: ['logFiles'] });
      setEdited({});
      onMessage({ type: 'success', text: t('rawFiles.saveSuccess') });
    },
    onError: (error: Error) => {
      // The server names the field and the accepted range.
      onMessage({ type: 'error', text: t('rawFiles.saveFail', { error: error.message }) });
    },
  });

  const getValue = <K extends keyof SystemSettings>(key: K): SystemSettings[K] | undefined => {
    if (key in edited) {
      return (edited as Partial<SystemSettings>)[key] as SystemSettings[K];
    }
    return settings?.[key];
  };

  const handleChange = (key: keyof UpdateSystemSettingsRequest, value: number | boolean) => {
    setEdited((prev) => ({ ...prev, [key]: value }));
  };

  // Only fields this edit changes are checked, like on the server: a stored
  // legacy value outside the range must not block saving something else.
  const invalidFields = (Object.keys(RAW_LOG_LIMITS) as RawLogLimitedField[]).filter(
    (field) => field in edited && !inRawLogRange(field, edited[field]),
  );
  const isModified = Object.keys(edited).length > 0;

  const numberField = (field: RawLogLimitedField, label: string, description: string) => {
    const { min, max } = RAW_LOG_LIMITS[field];
    const invalid = invalidFields.includes(field);
    const value = getValue(field);
    return (
      <div>
        <label htmlFor={`raw-log-${field}`} className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
          {label}
        </label>
        <input
          id={`raw-log-${field}`}
          type="number"
          min={min}
          max={max}
          value={Number.isFinite(value) ? (value as number) : ''}
          disabled={!canWrite}
          aria-invalid={invalid}
          onChange={(e) => handleChange(field, e.target.value === '' ? Number.NaN : Number(e.target.value))}
          className={`${inputClass} ${invalid ? 'border-red-500 dark:border-red-500' : 'border-slate-300 dark:border-slate-600'}`}
        />
        {invalid && (
          <p className="text-xs text-red-600 dark:text-red-400 mt-1">{t('rawFiles.settings.rangeHint', { min, max })}</p>
        )}
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{description}</p>
      </div>
    );
  };

  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 p-5 transition-colors">
      <div className="flex items-center justify-between mb-4 gap-3">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-slate-500 dark:text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          <h3 className="text-base font-semibold text-slate-800 dark:text-white">{t('rawFiles.settings.title')}</h3>
        </div>
        {canWrite && (
          <button
            onClick={() => updateMutation.mutate(edited)}
            disabled={!isModified || invalidFields.length > 0 || updateMutation.isPending}
            className="px-4 py-2 text-[13px] font-semibold bg-blue-600 text-white hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:bg-slate-300 transition-colors"
          >
            {updateMutation.isPending ? t('rawFiles.settings.saving') : t('rawFiles.settings.save')}
          </button>
        )}
      </div>

      <div className="space-y-4">
        {/* Raw log storage is mandatory since v2.17.1, see EnsureRawLogEnabled */}
        <div className="py-3 px-4 bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800 rounded-lg">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-emerald-600 dark:text-emerald-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <span className="text-sm font-semibold text-emerald-800 dark:text-emerald-200">{t('rawFiles.settings.alwaysOnLabel', { defaultValue: 'Raw 로그 저장 항상 활성화' })}</span>
              <p className="text-xs text-emerald-700 dark:text-emerald-300 mt-0.5">{t('rawFiles.settings.alwaysOnDescription', { defaultValue: 'v2.17.1 부터 LogCollector가 /etc/nginx/logs/access_raw.log를 직접 읽기 때문에 raw 로그 저장은 항상 활성화됩니다. 보관 기간 / 회전 / 압축은 아래에서 조정할 수 있습니다.' })}</p>
            </div>
          </div>
        </div>

        <div className="ml-8 space-y-4 border-l-2 border-slate-200 dark:border-slate-700 pl-4">
          {numberField('raw_log_max_size_mb', t('rawFiles.settings.maxSize'), t('rawFiles.settings.maxSizeDesc'))}
          {numberField('raw_log_retention_days', t('rawFiles.settings.retention'), t('rawFiles.settings.retentionDesc'))}

          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={getValue('raw_log_compress_rotated') ?? true}
              disabled={!canWrite}
              onChange={(e) => handleChange('raw_log_compress_rotated', e.target.checked)}
              className="w-4 h-4 rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 bg-white dark:bg-slate-700"
            />
            <div>
              <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('rawFiles.settings.compress')}</span>
              <p className="text-xs text-slate-500 dark:text-slate-400">{t('rawFiles.settings.compressDesc')}</p>
            </div>
          </label>

          <RawLogUsageEstimate usage={usage} retentionDays={getValue('raw_log_retention_days') ?? usage?.retention_days ?? 7} />
        </div>
      </div>
    </div>
  );
}

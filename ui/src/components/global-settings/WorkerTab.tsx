import { SettingField, CheckboxField, inputClass } from './SettingFields';
import type { TabContentProps } from './types';

export default function WorkerTab({ getNumberValue, getBoolValue, handleChange }: TabContentProps) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <SettingField settingKey="worker_processes">
          <input
            type="number"
            value={getNumberValue('worker_processes', 0)}
            onChange={(e) => handleChange('worker_processes', parseInt(e.target.value))}
            className={inputClass}
          />
        </SettingField>
        <SettingField settingKey="worker_connections">
          <input
            type="number"
            value={getNumberValue('worker_connections', 1024)}
            onChange={(e) => handleChange('worker_connections', parseInt(e.target.value))}
            className={inputClass}
          />
        </SettingField>
        <SettingField settingKey="worker_shutdown_timeout">
          <input
            type="number"
            min={0}
            max={86400}
            value={getNumberValue('worker_shutdown_timeout', 240)}
            onChange={(e) => handleChange('worker_shutdown_timeout', parseInt(e.target.value))}
            className={inputClass}
          />
        </SettingField>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 border-t border-slate-200 dark:border-slate-700 pt-6">
        <CheckboxField
          settingKey="multi_accept"
          checked={getBoolValue('multi_accept')}
          onChange={(checked) => handleChange('multi_accept', checked)}
        />
        <CheckboxField
          settingKey="use_epoll"
          checked={getBoolValue('use_epoll')}
          onChange={(checked) => handleChange('use_epoll', checked)}
        />
      </div>
    </div>
  );
}

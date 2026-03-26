import { SettingField, CheckboxField, inputClass } from './SettingFields';
import type { TabContentProps } from './types';

export default function SSLTab({ getStringValue, getBoolValue, handleChange }: TabContentProps) {
  return (
    <div className="space-y-6">
      <SettingField settingKey="ssl_protocols">
        <input
          type="text"
          value={getStringValue('ssl_protocols', 'TLSv1.2 TLSv1.3')}
          onChange={(e) => handleChange('ssl_protocols', e.target.value)}
          className={inputClass}
        />
      </SettingField>
      <SettingField settingKey="ssl_ciphers">
        <textarea
          value={getStringValue('ssl_ciphers', '')}
          onChange={(e) => handleChange('ssl_ciphers', e.target.value)}
          rows={3}
          className={`${inputClass} font-mono`}
        />
      </SettingField>
      <SettingField settingKey="ssl_ecdh_curve">
        <input
          type="text"
          value={getStringValue('ssl_ecdh_curve', 'x25519_mlkem768:X25519:secp256r1:secp384r1')}
          onChange={(e) => handleChange('ssl_ecdh_curve', e.target.value)}
          className={`${inputClass} font-mono`}
        />
      </SettingField>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <SettingField settingKey="ssl_session_cache">
          <input
            type="text"
            value={getStringValue('ssl_session_cache', 'shared:SSL:10m')}
            onChange={(e) => handleChange('ssl_session_cache', e.target.value)}
            className={inputClass}
          />
        </SettingField>
        <SettingField settingKey="ssl_session_timeout">
          <input
            type="text"
            value={getStringValue('ssl_session_timeout', '1d')}
            onChange={(e) => handleChange('ssl_session_timeout', e.target.value)}
            className={inputClass}
          />
        </SettingField>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-slate-200 dark:border-slate-700 pt-6">
        <CheckboxField
          settingKey="ssl_prefer_server_ciphers"
          checked={getBoolValue('ssl_prefer_server_ciphers')}
          onChange={(checked) => handleChange('ssl_prefer_server_ciphers', checked)}
        />
        <CheckboxField
          settingKey="ssl_stapling"
          checked={getBoolValue('ssl_stapling')}
          onChange={(checked) => handleChange('ssl_stapling', checked)}
        />
        <CheckboxField
          settingKey="ssl_stapling_verify"
          checked={getBoolValue('ssl_stapling_verify')}
          onChange={(checked) => handleChange('ssl_stapling_verify', checked)}
        />
        <CheckboxField
          settingKey="ssl_session_tickets"
          checked={getBoolValue('ssl_session_tickets')}
          onChange={(checked) => handleChange('ssl_session_tickets', checked)}
        />
      </div>
    </div>
  );
}

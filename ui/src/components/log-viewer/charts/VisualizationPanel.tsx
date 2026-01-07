import { memo } from 'react';
import { useTranslation } from 'react-i18next';
import { BarChart } from './BarChart';
import { StatusCodeChart } from './StatusCodeChart';
import type { VisualizationPanelProps } from '../types';

export const VisualizationPanel = memo(function VisualizationPanel({
  stats,
  logType,
  isLoading
}: VisualizationPanelProps) {
  const { t } = useTranslation('logs');
  if (isLoading) {
    return (
      <div className="bg-slate-50 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-8 text-center">
        <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">{t('charts.loading')}</p>
      </div>
    );
  }

  if (!stats) return null;

  // Prepare data for charts
  const statusCodeData = stats.top_status_codes?.map(s => ({
    label: `${s.status_code}`,
    value: s.count,
    color: s.status_code >= 500 ? 'bg-red-500' :
      s.status_code >= 400 ? 'bg-yellow-500' :
        s.status_code >= 300 ? 'bg-blue-500' : 'bg-green-500'
  })) || [];

  const topIPsData = stats.top_client_ips?.map(ip => ({
    label: ip.client_ip,
    value: ip.count,
    color: 'bg-indigo-500'
  })) || [];

  const topURIsData = stats.top_attacked_uris?.map(u => ({
    label: u.uri,
    value: u.count,
    color: 'bg-orange-500'
  })) || [];

  const topRulesData = stats.top_rule_ids?.map(r => ({
    label: `${r.rule_id}: ${r.message?.slice(0, 30) || 'Unknown'}`,
    value: r.count,
    color: 'bg-red-500'
  })) || [];

  const topUserAgentsData = stats.top_user_agents?.map(ua => ({
    label: ua.user_agent.length > 50 ? ua.user_agent.slice(0, 50) + '...' : ua.user_agent,
    value: ua.count,
    color: 'bg-purple-500'
  })) || [];

  const countryData = stats.top_countries?.slice(0, 10).map(c => ({
    label: `${c.country_code} (${c.country})`,
    value: c.count,
    color: 'bg-emerald-500'
  })) || [];

  return (
    <div className="bg-slate-50 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Status Codes Chart - Access logs only */}
        {logType === 'access' && stats.top_status_codes && stats.top_status_codes.length > 0 && (
          <StatusCodeChart data={stats.top_status_codes} />
        )}

        {/* Top IPs */}
        {topIPsData.length > 0 && (
          <BarChart data={topIPsData} title={t('stats.topClientIps')} maxItems={8} />
        )}

        {/* Countries */}
        {countryData.length > 0 && (
          <BarChart data={countryData} title={t('stats.topCountries')} maxItems={8} />
        )}

        {/* Top User Agents */}
        {topUserAgentsData.length > 0 && (
          <BarChart data={topUserAgentsData} title={t('stats.topUserAgents')} maxItems={8} />
        )}

        {/* Top URIs - Access logs */}
        {logType === 'access' && topURIsData.length > 0 && (
          <BarChart data={topURIsData} title={t('stats.topUris')} maxItems={8} />
        )}

        {/* Top Rules - ModSec logs */}
        {logType === 'modsec' && topRulesData.length > 0 && (
          <BarChart data={topRulesData} title={t('stats.topWafRules')} maxItems={8} />
        )}

        {/* Status Code Bar Chart */}
        {logType === 'access' && statusCodeData.length > 0 && (
          <BarChart data={statusCodeData} title={t('stats.statusCodeDist')} maxItems={10} />
        )}
      </div>
    </div>
  );
});

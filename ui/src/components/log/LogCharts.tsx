import { memo } from "react";
import type { LogStats, CountryStat } from "../../types/log";

// Simple Bar Chart Component
interface BarChartProps {
  data: { label: string; value: number; color?: string }[];
  title: string;
  maxItems?: number;
}

export const BarChart = memo(function BarChart({
  data,
  title,
  maxItems = 10,
}: BarChartProps) {
  const displayData = data.slice(0, maxItems);
  const maxValue = Math.max(...displayData.map((d) => d.value), 1);

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4">
      <h4 className="text-sm font-semibold text-slate-700 mb-3">{title}</h4>
      <div className="space-y-2">
        {displayData.length === 0 ? (
          <p className="text-xs text-slate-400 text-center py-4">
            No data available
          </p>
        ) : (
          displayData.map((item, index) => (
            <div key={index} className="flex items-center gap-2">
              <span
                className="text-xs text-slate-600 w-36 truncate font-mono"
                title={item.label}
              >
                {item.label}
              </span>
              <div className="flex-1 h-5 bg-slate-100 rounded-full overflow-hidden min-w-[60px]">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    item.color || "bg-primary-500"
                  }`}
                  style={{ width: `${(item.value / maxValue) * 100}%` }}
                />
              </div>
              <span className="text-xs font-medium text-slate-700 w-14 text-right">
                {item.value.toLocaleString()}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
});

// Status Code Pie/Donut Chart
interface StatusCodeChartProps {
  data: { status_code: number; count: number }[];
}

export const StatusCodeChart = memo(function StatusCodeChart({
  data,
}: StatusCodeChartProps) {
  const total = data.reduce((sum, d) => sum + d.count, 0);

  const getStatusColor = (code: number) => {
    if (code >= 500) return { bg: "bg-red-500", text: "text-red-600" };
    if (code >= 400) return { bg: "bg-yellow-500", text: "text-yellow-600" };
    if (code >= 300) return { bg: "bg-blue-500", text: "text-blue-600" };
    return { bg: "bg-green-500", text: "text-green-600" };
  };

  // Calculate cumulative percentages for the donut
  let cumulative = 0;
  const segments = data.map((d) => {
    const percentage = (d.count / total) * 100;
    const segment = {
      ...d,
      percentage,
      startOffset: cumulative,
      color: getStatusColor(d.status_code),
    };
    cumulative += percentage;
    return segment;
  });

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4">
      <h4 className="text-sm font-semibold text-slate-700 mb-3">
        Status Codes
      </h4>
      <div className="flex items-center gap-4">
        {/* Simple donut representation using stacked bars */}
        <div className="relative w-24 h-24">
          <svg viewBox="0 0 36 36" className="w-24 h-24 transform -rotate-90">
            {segments.map((seg, i) => (
              <circle
                key={i}
                cx="18"
                cy="18"
                r="15.915"
                fill="transparent"
                stroke="currentColor"
                strokeWidth="3"
                strokeDasharray={`${seg.percentage} ${100 - seg.percentage}`}
                strokeDashoffset={-seg.startOffset}
                className={seg.color.text}
              />
            ))}
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xs font-bold text-slate-700">
              {total.toLocaleString()}
            </span>
          </div>
        </div>

        {/* Legend */}
        <div className="flex-1 space-y-1">
          {segments.slice(0, 6).map((seg, i) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <span className={`w-2 h-2 rounded-full ${seg.color.bg}`} />
              <span className="text-slate-600">{seg.status_code}</span>
              <span className="text-slate-400 ml-auto">
                {seg.percentage.toFixed(1)}%
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
});

// Visualization Panel Component
interface VisualizationPanelProps {
  stats: LogStats | undefined;
  logType?: "access" | "error" | "modsec";
  isLoading: boolean;
}

export const VisualizationPanel = memo(function VisualizationPanel({
  stats,
  logType,
  isLoading,
}: VisualizationPanelProps) {
  if (isLoading) {
    return (
      <div className="bg-slate-50 rounded-xl border border-slate-200 p-8 text-center">
        <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-sm text-slate-500 mt-2">Loading visualization...</p>
      </div>
    );
  }

  if (!stats) return null;

  // Prepare data for charts
  const statusCodeData =
    stats.top_status_codes?.map((s) => ({
      label: `${s.status_code}`,
      value: s.count,
      color:
        s.status_code >= 500
          ? "bg-red-500"
          : s.status_code >= 400
          ? "bg-yellow-500"
          : s.status_code >= 300
          ? "bg-blue-500"
          : "bg-green-500",
    })) || [];

  const topIPsData =
    stats.top_client_ips?.map((ip) => ({
      label: ip.client_ip,
      value: ip.count,
      color: "bg-indigo-500",
    })) || [];

  const topURIsData =
    stats.top_attacked_uris?.map((u) => ({
      label: u.uri,
      value: u.count,
      color: "bg-orange-500",
    })) || [];

  const topRulesData =
    stats.top_rule_ids?.map((r) => ({
      label: `${r.rule_id}: ${r.message?.slice(0, 30) || "Unknown"}`,
      value: r.count,
      color: "bg-red-500",
    })) || [];

  const topUserAgentsData =
    stats.top_user_agents?.map((ua) => ({
      label:
        ua.user_agent.length > 50
          ? ua.user_agent.slice(0, 50) + "..."
          : ua.user_agent,
      value: ua.count,
      color: "bg-purple-500",
    })) || [];

  const countryData =
    stats.top_countries?.map((c) => ({
      label: c.country_code,
      value: c.count,
      color: "bg-emerald-500",
    })) || [];

  return (
    <div className="bg-slate-50 rounded-xl border border-slate-200 p-4">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Status Codes Chart - Access logs only */}
        {logType === "access" &&
          stats.top_status_codes &&
          stats.top_status_codes.length > 0 && (
            <StatusCodeChart data={stats.top_status_codes} />
          )}

        {/* Top IPs */}
        {topIPsData.length > 0 && (
          <BarChart data={topIPsData} title="Top Client IPs" maxItems={8} />
        )}

        {/* Countries */}
        {countryData.length > 0 && (
          <BarChart data={countryData} title="Top Countries" maxItems={8} />
        )}

        {/* Top User Agents */}
        {topUserAgentsData.length > 0 && (
          <BarChart
            data={topUserAgentsData}
            title="Top User Agents"
            maxItems={8}
          />
        )}

        {/* Top URIs - Access logs */}
        {logType === "access" && topURIsData.length > 0 && (
          <BarChart data={topURIsData} title="Top URIs" maxItems={8} />
        )}

        {/* Top Rules - ModSec logs */}
        {logType === "modsec" && topRulesData.length > 0 && (
          <BarChart data={topRulesData} title="Top WAF Rules" maxItems={8} />
        )}

        {/* Status Code Bar Chart */}
        {logType === "access" && statusCodeData.length > 0 && (
          <BarChart
            data={statusCodeData}
            title="Status Code Distribution"
            maxItems={10}
          />
        )}
      </div>
    </div>
  );
});

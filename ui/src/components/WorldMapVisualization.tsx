import { useMemo, memo, useState } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
  type Geography as GeographyType,
} from "react-simple-maps";

interface GeoData {
  country_code: string;
  country: string;
  count: number;
  lat: number;
  lng: number;
  percentage: number;
}

interface WorldMapVisualizationProps {
  data: GeoData[];
  isLoading?: boolean;
}

// World map TopoJSON URL with ISO_A2 codes
const GEO_URL =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// Numeric ID to ISO2 mapping for world-atlas countries-110m.json
const NUMERIC_TO_ISO2: Record<string, string> = {
  "4": "AF",
  "8": "AL",
  "12": "DZ",
  "24": "AO",
  "32": "AR",
  "36": "AU",
  "40": "AT",
  "50": "BD",
  "56": "BE",
  "68": "BO",
  "76": "BR",
  "100": "BG",
  "104": "MM",
  "116": "KH",
  "120": "CM",
  "124": "CA",
  "144": "LK",
  "152": "CL",
  "156": "CN",
  "158": "TW",
  "170": "CO",
  "178": "CG",
  "180": "CD",
  "188": "CR",
  "191": "HR",
  "192": "CU",
  "196": "CY",
  "203": "CZ",
  "208": "DK",
  "214": "DO",
  "218": "EC",
  "818": "EG",
  "222": "SV",
  "231": "ET",
  "233": "EE",
  "246": "FI",
  "250": "FR",
  "266": "GA",
  "276": "DE",
  "288": "GH",
  "300": "GR",
  "320": "GT",
  "332": "HT",
  "340": "HN",
  "344": "HK",
  "348": "HU",
  "352": "IS",
  "356": "IN",
  "360": "ID",
  "364": "IR",
  "368": "IQ",
  "372": "IE",
  "376": "IL",
  "380": "IT",
  "384": "CI",
  "392": "JP",
  "398": "KZ",
  "400": "JO",
  "404": "KE",
  "408": "KP",
  "410": "KR",
  "414": "KW",
  "417": "KG",
  "418": "LA",
  "422": "LB",
  "426": "LS",
  "428": "LV",
  "434": "LY",
  "440": "LT",
  "442": "LU",
  "450": "MG",
  "454": "MW",
  "458": "MY",
  "466": "ML",
  "478": "MR",
  "484": "MX",
  "496": "MN",
  "498": "MD",
  "504": "MA",
  "508": "MZ",
  "512": "OM",
  "516": "NA",
  "524": "NP",
  "528": "NL",
  "554": "NZ",
  "558": "NI",
  "562": "NE",
  "566": "NG",
  "578": "NO",
  "586": "PK",
  "591": "PA",
  "598": "PG",
  "600": "PY",
  "604": "PE",
  "608": "PH",
  "616": "PL",
  "620": "PT",
  "630": "PR",
  "634": "QA",
  "642": "RO",
  "643": "RU",
  "646": "RW",
  "682": "SA",
  "686": "SN",
  "688": "RS",
  "694": "SL",
  "702": "SG",
  "703": "SK",
  "704": "VN",
  "705": "SI",
  "706": "SO",
  "710": "ZA",
  "716": "ZW",
  "724": "ES",
  "728": "SS",
  "729": "SD",
  "740": "SR",
  "752": "SE",
  "756": "CH",
  "760": "SY",
  "762": "TJ",
  "764": "TH",
  "780": "TT",
  "784": "AE",
  "788": "TN",
  "792": "TR",
  "795": "TM",
  "800": "UG",
  "804": "UA",
  "807": "MK",
  "826": "GB",
  "834": "TZ",
  "840": "US",
  "854": "BF",
  "858": "UY",
  "860": "UZ",
  "862": "VE",
  "887": "YE",
  "894": "ZM",
};

// Country to region mapping (ISO2)
const COUNTRY_REGIONS: Record<string, string> = {
  US: "north-america",
  CA: "north-america",
  MX: "north-america",
  GT: "north-america",
  CU: "north-america",
  BR: "south-america",
  AR: "south-america",
  CL: "south-america",
  CO: "south-america",
  PE: "south-america",
  VE: "south-america",
  EC: "south-america",
  UY: "south-america",
  PY: "south-america",
  BO: "south-america",
  GB: "europe",
  DE: "europe",
  FR: "europe",
  IT: "europe",
  ES: "europe",
  NL: "europe",
  BE: "europe",
  PT: "europe",
  PL: "europe",
  SE: "europe",
  NO: "europe",
  FI: "europe",
  DK: "europe",
  AT: "europe",
  CH: "europe",
  IE: "europe",
  GR: "europe",
  RO: "europe",
  HU: "europe",
  CZ: "europe",
  BG: "europe",
  UA: "europe",
  LT: "europe",
  LV: "europe",
  EE: "europe",
  SK: "europe",
  SI: "europe",
  HR: "europe",
  RS: "europe",
  BY: "europe",
  MD: "europe",
  RU: "russia",
  ZA: "africa",
  EG: "africa",
  NG: "africa",
  KE: "africa",
  MA: "africa",
  TN: "africa",
  GH: "africa",
  ET: "africa",
  TZ: "africa",
  DZ: "africa",
  LY: "africa",
  SD: "africa",
  SA: "middle-east",
  AE: "middle-east",
  IL: "middle-east",
  TR: "middle-east",
  IR: "middle-east",
  IQ: "middle-east",
  QA: "middle-east",
  KW: "middle-east",
  OM: "middle-east",
  YE: "middle-east",
  CN: "asia",
  JP: "asia",
  KR: "asia",
  IN: "asia",
  SG: "asia",
  HK: "asia",
  TW: "asia",
  TH: "asia",
  VN: "asia",
  ID: "asia",
  MY: "asia",
  PH: "asia",
  PK: "asia",
  BD: "asia",
  KZ: "asia",
  UZ: "asia",
  MM: "asia",
  KH: "asia",
  MN: "asia",
  NP: "asia",
  AU: "oceania",
  NZ: "oceania",
  PG: "oceania",
};

const REGION_NAMES: Record<string, string> = {
  "north-america": "North America",
  "south-america": "South America",
  europe: "Europe",
  russia: "Russia",
  africa: "Africa",
  "middle-east": "Middle East",
  asia: "Asia",
  oceania: "Oceania",
};

const REGIONS = [
  "north-america",
  "south-america",
  "europe",
  "russia",
  "africa",
  "middle-east",
  "asia",
  "oceania",
];

function getCountryColor(percentage: number, maxPercentage: number): string {
  if (percentage === 0) return "#1e293b";
  const ratio = maxPercentage > 0 ? percentage / maxPercentage : 0;
  if (ratio >= 0.6) return "#1d4ed8";
  if (ratio >= 0.3) return "#3b82f6";
  if (ratio >= 0.1) return "#60a5fa";
  return "#93c5fd";
}

function getRegionColor(percentage: number, maxPercentage: number): string {
  if (percentage === 0) return "#1e293b";
  const ratio = maxPercentage > 0 ? percentage / maxPercentage : 0;
  if (ratio >= 0.6) return "#1d4ed8";
  if (ratio >= 0.3) return "#3b82f6";
  if (ratio >= 0.1) return "#60a5fa";
  return "#93c5fd";
}

function WorldMapVisualization({
  data,
  isLoading,
}: WorldMapVisualizationProps) {
  const [tooltipContent, setTooltipContent] = useState("");
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });

  // Create a map of country data by ISO2 code (directly from API)
  const countryDataMap = useMemo(() => {
    const map: Record<string, GeoData> = {};
    data.forEach((d) => {
      if (d.country_code) {
        map[d.country_code.toUpperCase()] = d;
      }
    });
    return map;
  }, [data]);

  const maxPercentage = useMemo(() => {
    return Math.max(...data.map((d) => d.percentage), 1);
  }, [data]);

  const regionData = useMemo(() => {
    const result: Record<string, { count: number; percentage: number }> = {};
    REGIONS.forEach((region) => {
      result[region] = { count: 0, percentage: 0 };
    });
    data.forEach((country) => {
      const region = COUNTRY_REGIONS[country.country_code?.toUpperCase()];
      if (region && result[region]) {
        result[region].count += country.count;
        result[region].percentage += country.percentage;
      }
    });
    return result;
  }, [data]);

  const maxRegionPercentage = useMemo(() => {
    return Math.max(...Object.values(regionData).map((r) => r.percentage), 1);
  }, [regionData]);

  const totalRequests = useMemo(() => {
    return data.reduce((sum, d) => sum + d.count, 0);
  }, [data]);

  const sortedRegions = useMemo(() => {
    return Object.entries(regionData)
      .filter(([_, d]) => d.count > 0)
      .sort((a, b) => b[1].count - a[1].count);
  }, [regionData]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full bg-slate-900 rounded-lg">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="flex h-full bg-slate-900 rounded-lg overflow-hidden">
      {/* Map Section */}
      <div className="flex-1 relative">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{
            scale: 120,
            center: [0, 30],
          }}
          style={{
            width: "100%",
            height: "100%",
            backgroundColor: "#0c1929",
          }}
        >
          <ZoomableGroup>
            <Geographies geography={GEO_URL}>
              {({ geographies }: { geographies: GeographyType[] }) =>
                geographies.map((geo: GeographyType) => {
                  // Get ISO2 code from numeric ID
                  const numericId = geo.id;
                  const iso2 = NUMERIC_TO_ISO2[numericId];
                  const countryData = iso2 ? countryDataMap[iso2] : undefined;
                  const hasData = countryData && countryData.count > 0;
                  const color = hasData
                    ? getCountryColor(countryData.percentage, maxPercentage)
                    : "#1e293b";

                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={color}
                      stroke="#334155"
                      strokeWidth={0.5}
                      onMouseEnter={(evt) => {
                        if (hasData && countryData) {
                          setTooltipContent(
                            `${
                              countryData.country
                            }: ${countryData.count.toLocaleString()} (${countryData.percentage.toFixed(
                              1
                            )}%)`
                          );
                          setTooltipPosition({
                            x: evt.clientX,
                            y: evt.clientY,
                          });
                        }
                      }}
                      onMouseLeave={() => {
                        setTooltipContent("");
                      }}
                      style={{
                        default: {
                          outline: "none",
                          transition: "all 0.3s",
                        },
                        hover: {
                          fill: hasData ? "#60a5fa" : "#334155",
                          outline: "none",
                          cursor: hasData ? "pointer" : "default",
                        },
                        pressed: {
                          outline: "none",
                        },
                      }}
                    />
                  );
                })
              }
            </Geographies>
          </ZoomableGroup>
        </ComposableMap>

        {/* Tooltip */}
        {tooltipContent && (
          <div
            className="fixed z-50 px-2 py-1 text-xs text-white bg-slate-800 rounded shadow-lg pointer-events-none"
            style={{
              left: tooltipPosition.x + 10,
              top: tooltipPosition.y - 30,
            }}
          >
            {tooltipContent}
          </div>
        )}
      </div>

      {/* Stats Panel */}
      <div className="w-44 border-l border-slate-700/50 p-3 flex flex-col bg-slate-800/30">
        <div className="text-xs text-slate-400 uppercase tracking-wide mb-3 font-medium">
          Traffic by Region
        </div>

        <div className="flex-1 space-y-2 overflow-auto pr-3 custom-scrollbar">
          {sortedRegions.length > 0 ? (
            sortedRegions.map(([regionId, region]) => (
              <div key={regionId} className="group">
                <div className="flex items-center justify-between text-xs mb-1">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2.5 h-2.5 rounded-sm"
                      style={{
                        backgroundColor: getRegionColor(
                          region.percentage,
                          maxRegionPercentage
                        ),
                      }}
                    />
                    <span className="text-slate-300 font-medium">
                      {REGION_NAMES[regionId]}
                    </span>
                  </div>
                  <span className="text-slate-400">
                    {region.percentage.toFixed(0)}%
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1 bg-slate-700 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${region.percentage}%`,
                        backgroundColor: getRegionColor(
                          region.percentage,
                          maxRegionPercentage
                        ),
                      }}
                    />
                  </div>
                  <span className="text-white text-xs font-semibold min-w-[40px] text-right">
                    {region.count >= 1000
                      ? `${(region.count / 1000).toFixed(1)}K`
                      : region.count}
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div className="text-slate-500 text-xs text-center py-4">
              No traffic data
            </div>
          )}
        </div>

        {/* Legend */}
        <div className="border-t border-slate-700/50 pt-3 mt-3">
          <div className="text-xs text-slate-500 mb-1.5">Intensity</div>
          <div className="flex gap-0.5">
            <div className="flex-1 h-2 rounded-l bg-slate-700"></div>
            <div className="flex-1 h-2 bg-blue-400"></div>
            <div className="flex-1 h-2 bg-blue-500"></div>
            <div className="flex-1 h-2 rounded-r bg-blue-700"></div>
          </div>
          <div className="flex justify-between text-[10px] text-slate-500 mt-1">
            <span>Low</span>
            <span>High</span>
          </div>
        </div>

        {/* Total */}
        {totalRequests > 0 && (
          <div className="border-t border-slate-700/50 pt-3 mt-3 text-center">
            <div className="text-xl font-bold text-white">
              {totalRequests >= 1000
                ? `${(totalRequests / 1000).toFixed(1)}K`
                : totalRequests}
            </div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wide">
              Total Requests
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default memo(WorldMapVisualization);

import { useMemo, memo, useState, type ComponentProps } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
  useZoomPanContext,
} from "react-simple-maps";
import {
  COUNTRY_REGIONS,
  DOT_COORDINATES,
  featureToISO2,
} from "./worldMapCountries";

// react-simple-maps v5 re-exports `Geography` as a component only, so the
// feature type is taken from the component's own props rather than imported.
type GeographyType = ComponentProps<typeof Geography>["geography"];

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

// World map TopoJSON; feature ids are zero-padded ISO 3166-1 numeric codes
const GEO_URL =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

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

type CursorPosition = Pick<MouseEvent, "clientX" | "clientY">;

interface CountryDotsProps {
  countries: GeoData[];
  maxPercentage: number;
  onEnter: (country: GeoData, cursor: CursorPosition) => void;
  onLeave: () => void;
}

// Dots for the countries in DOT_COORDINATES. Radius and outline are divided by
// the zoom level, so a dot keeps its size on screen and close neighbours such
// as Hong Kong and Macao separate as the map zooms in.
function CountryDots({
  countries,
  maxPercentage,
  onEnter,
  onLeave,
}: CountryDotsProps) {
  const { k } = useZoomPanContext();
  return (
    <>
      {countries.map((country) => (
        <Marker
          key={country.country_code}
          coordinates={DOT_COORDINATES[country.country_code.toUpperCase()]}
        >
          <circle
            r={4 / k}
            fill={getCountryColor(country.percentage, maxPercentage)}
            stroke="#334155"
            strokeWidth={1 / k}
            onMouseEnter={(evt) => onEnter(country, evt)}
            onMouseLeave={onLeave}
            className="npg-geography npg-geography--interactive"
          />
        </Marker>
      ))}
    </>
  );
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

  // Countries with traffic that the map has no shape for, shown as dots
  const dotCountries = useMemo(
    () =>
      data.filter(
        (d) => d.count > 0 && DOT_COORDINATES[d.country_code?.toUpperCase()],
      ),
    [data],
  );

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

  const showTooltip = (country: GeoData, cursor: CursorPosition) => {
    setTooltipContent(
      `${country.country}: ${country.count.toLocaleString()} (${country.percentage.toFixed(1)}%)`,
    );
    setTooltipPosition({ x: cursor.clientX, y: cursor.clientY });
  };
  const hideTooltip = () => setTooltipContent("");

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
                  const iso2 = featureToISO2(geo.id, geo.properties?.name);
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
                          showTooltip(countryData, evt);
                        }
                      }}
                      onMouseLeave={hideTooltip}
                      className={
                        hasData
                          ? "npg-geography npg-geography--interactive"
                          : "npg-geography"
                      }
                    />
                  );
                })
              }
            </Geographies>
            <CountryDots
              countries={dotCountries}
              maxPercentage={maxPercentage}
              onEnter={showTooltip}
              onLeave={hideTooltip}
            />
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

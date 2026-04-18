import { useEffect, useRef, useState, useCallback } from 'react';

interface GeoData {
  country_code: string;
  country: string;
  count: number;
  lat: number;
  lng: number;
  percentage: number;
}

interface GlobeVisualizationProps {
  data: GeoData[];
  isLoading?: boolean;
}

// Country coordinates (ISO 3166-1 alpha-2 to lat/lng)
const COUNTRY_COORDS: Record<string, [number, number]> = {
  'US': [37.0902, -95.7129],
  'CN': [35.8617, 104.1954],
  'JP': [36.2048, 138.2529],
  'KR': [35.9078, 127.7669],
  'DE': [51.1657, 10.4515],
  'GB': [55.3781, -3.4360],
  'FR': [46.2276, 2.2137],
  'BR': [-14.2350, -51.9253],
  'IN': [20.5937, 78.9629],
  'RU': [61.5240, 105.3188],
  'AU': [-25.2744, 133.7751],
  'CA': [56.1304, -106.3468],
  'IT': [41.8719, 12.5674],
  'ES': [40.4637, -3.7492],
  'NL': [52.1326, 5.2913],
  'SG': [1.3521, 103.8198],
  'HK': [22.3193, 114.1694],
  'TW': [23.6978, 120.9605],
  'VN': [14.0583, 108.2772],
  'TH': [15.8700, 100.9925],
  'ID': [-0.7893, 113.9213],
  'MY': [4.2105, 101.9758],
  'PH': [12.8797, 121.7740],
  'PK': [30.3753, 69.3451],
  'BD': [23.6850, 90.3563],
  'MX': [23.6345, -102.5528],
  'AR': [-38.4161, -63.6167],
  'CL': [-35.6751, -71.5430],
  'CO': [4.5709, -74.2973],
  'PE': [-9.1900, -75.0152],
  'VE': [6.4238, -66.5897],
  'ZA': [-30.5595, 22.9375],
  'EG': [26.8206, 30.8025],
  'NG': [9.0820, 8.6753],
  'KE': [-0.0236, 37.9062],
  'SA': [23.8859, 45.0792],
  'AE': [23.4241, 53.8478],
  'IL': [31.0461, 34.8516],
  'TR': [38.9637, 35.2433],
  'PL': [51.9194, 19.1451],
  'UA': [48.3794, 31.1656],
  'CZ': [49.8175, 15.4730],
  'SE': [60.1282, 18.6435],
  'NO': [60.4720, 8.4689],
  'FI': [61.9241, 25.7482],
  'DK': [56.2639, 9.5018],
  'AT': [47.5162, 14.5501],
  'CH': [46.8182, 8.2275],
  'BE': [50.5039, 4.4699],
  'PT': [39.3999, -8.2245],
  'GR': [39.0742, 21.8243],
  'RO': [45.9432, 24.9668],
  'HU': [47.1625, 19.5033],
  'NZ': [-40.9006, 174.8860],
  'IE': [53.1424, -7.6921],
  'BG': [42.7339, 25.4858],
  'LT': [55.1694, 23.8813],
  'LV': [56.8796, 24.6032],
  'EE': [58.5953, 25.0136],
  'HR': [45.1, 15.2],
  'SK': [48.669, 19.699],
  'SI': [46.1512, 14.9955],
  'RS': [44.0165, 21.0059],
  'BA': [43.9159, 17.6791],
  'MK': [41.5124, 21.7453],
  'AL': [41.1533, 20.1683],
  'MT': [35.9375, 14.3754],
  'CY': [35.1264, 33.4299],
  'LU': [49.8153, 6.1296],
  'IS': [64.9631, -19.0208],
  'MD': [47.4116, 28.3699],
  'BY': [53.7098, 27.9534],
};

// Get color based on request count (blue gradient)
function getColor(percentage: number): string {
  const intensity = Math.min(255, Math.floor(100 + percentage * 1.5));
  return `rgb(59, ${Math.floor(130 + (1 - percentage / 100) * 60)}, ${intensity})`;
}

// Convert lat/lng to 3D coordinates for globe projection
function latLngTo3D(lat: number, lng: number, radius: number): [number, number, number] {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  const x = -radius * Math.sin(phi) * Math.cos(theta);
  const y = radius * Math.cos(phi);
  const z = radius * Math.sin(phi) * Math.sin(theta);
  return [x, y, z];
}

// Project 3D point to 2D screen coordinates
function project3Dto2D(
  x: number, y: number, z: number,
  rotationY: number, rotationX: number,
  width: number, height: number
): [number, number, boolean] {
  // Apply Y rotation (horizontal)
  const cosY = Math.cos(rotationY);
  const sinY = Math.sin(rotationY);
  const x1 = x * cosY - z * sinY;
  const z1 = x * sinY + z * cosY;

  // Apply X rotation (tilt)
  const cosX = Math.cos(rotationX);
  const sinX = Math.sin(rotationX);
  const y1 = y * cosX - z1 * sinX;
  const z2 = y * sinX + z1 * cosX;

  // Perspective projection
  const scale = 400 / (400 + z2);
  const screenX = width / 2 + x1 * scale;
  const screenY = height / 2 + y1 * scale;

  return [screenX, screenY, z2 > 0]; // isVisible: point is on front side
}

export default function GlobeVisualization({ data, isLoading }: GlobeVisualizationProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [rotation, setRotation] = useState({ x: 0.3, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [lastMouse, setLastMouse] = useState({ x: 0, y: 0 });
  const [hoveredCountry, setHoveredCountry] = useState<GeoData | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const animationRef = useRef<number | undefined>(undefined);

  // Process data with coordinates
  const processedData = data.map(item => ({
    ...item,
    coords: COUNTRY_COORDS[item.country_code] || [0, 0]
  }));

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = container.clientWidth;
    const height = container.clientHeight;
    canvas.width = width * window.devicePixelRatio;
    canvas.height = height * window.devicePixelRatio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    const radius = Math.min(width, height) * 0.35;
    const centerX = width / 2;
    const centerY = height / 2;

    // Clear canvas
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, width, height);

    // Draw globe gradient (sphere effect)
    const gradient = ctx.createRadialGradient(
      centerX - radius * 0.3, centerY - radius * 0.3, 0,
      centerX, centerY, radius
    );
    gradient.addColorStop(0, '#1e3a5f');
    gradient.addColorStop(0.5, '#1e293b');
    gradient.addColorStop(1, '#0f172a');

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw globe outline
    ctx.strokeStyle = '#334155';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw latitude lines
    ctx.strokeStyle = 'rgba(100, 116, 139, 0.3)';
    ctx.lineWidth = 0.5;
    for (let lat = -60; lat <= 60; lat += 30) {
      ctx.beginPath();
      for (let lng = 0; lng <= 360; lng += 5) {
        const [x, y, z] = latLngTo3D(lat, lng, radius);
        const [sx, sy, visible] = project3Dto2D(x, y, z, rotation.y, rotation.x, width, height);
        if (visible) {
          if (lng === 0) ctx.moveTo(sx, sy);
          else ctx.lineTo(sx, sy);
        }
      }
      ctx.stroke();
    }

    // Draw longitude lines
    for (let lng = 0; lng < 360; lng += 30) {
      ctx.beginPath();
      for (let lat = -90; lat <= 90; lat += 5) {
        const [x, y, z] = latLngTo3D(lat, lng, radius);
        const [sx, sy, visible] = project3Dto2D(x, y, z, rotation.y, rotation.x, width, height);
        if (visible) {
          if (lat === -90) ctx.moveTo(sx, sy);
          else ctx.lineTo(sx, sy);
        }
      }
      ctx.stroke();
    }

    // Sort by z-order (back to front)
    const sortedData = processedData
      .map(item => {
        const [x, y, z] = latLngTo3D(item.coords[0], item.coords[1], radius);
        const [sx, sy, visible] = project3Dto2D(x, y, z, rotation.y, rotation.x, width, height);
        return { ...item, sx, sy, visible, z: z };
      })
      .filter(item => item.visible)
      .sort((a, b) => a.z - b.z); // Sort by depth

    // Draw data points (arcs and dots)
    sortedData.forEach(item => {
      const size = Math.max(4, Math.min(20, 4 + item.percentage * 0.3));

      // Draw glow
      const glowGradient = ctx.createRadialGradient(item.sx, item.sy, 0, item.sx, item.sy, size * 2);
      glowGradient.addColorStop(0, getColor(item.percentage) + '80');
      glowGradient.addColorStop(1, 'transparent');
      ctx.beginPath();
      ctx.arc(item.sx, item.sy, size * 2, 0, Math.PI * 2);
      ctx.fillStyle = glowGradient;
      ctx.fill();

      // Draw dot
      ctx.beginPath();
      ctx.arc(item.sx, item.sy, size, 0, Math.PI * 2);
      ctx.fillStyle = getColor(item.percentage);
      ctx.fill();
      ctx.strokeStyle = '#ffffff40';
      ctx.lineWidth = 1;
      ctx.stroke();
    });

    // Draw arcs (connecting lines to center for top countries)
    const topCountries = sortedData.slice(0, 5);
    topCountries.forEach(item => {
      if (!item.visible) return;

      ctx.beginPath();
      ctx.moveTo(centerX, centerY);

      // Create curved arc
      const midX = (centerX + item.sx) / 2;
      const midY = (centerY + item.sy) / 2 - 30;
      ctx.quadraticCurveTo(midX, midY, item.sx, item.sy);

      ctx.strokeStyle = getColor(item.percentage) + '60';
      ctx.lineWidth = 1 + item.percentage * 0.03;
      ctx.stroke();
    });

  }, [rotation, processedData]);

  // Animation loop for auto-rotation
  useEffect(() => {
    let lastTime = 0;
    const animate = (time: number) => {
      if (!isDragging) {
        const delta = time - lastTime;
        setRotation(prev => ({
          ...prev,
          y: prev.y + delta * 0.0001
        }));
      }
      lastTime = time;
      draw();
      animationRef.current = requestAnimationFrame(animate);
    };

    animationRef.current = requestAnimationFrame(animate);
    return () => {
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, [isDragging, draw]);

  // Mouse handlers for interaction
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setLastMouse({ x: e.clientX, y: e.clientY });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    setMousePos({ x: e.clientX, y: e.clientY });

    if (isDragging) {
      const deltaX = e.clientX - lastMouse.x;
      const deltaY = e.clientY - lastMouse.y;
      setRotation(prev => ({
        x: Math.max(-Math.PI / 2, Math.min(Math.PI / 2, prev.x + deltaY * 0.005)),
        y: prev.y + deltaX * 0.005
      }));
      setLastMouse({ x: e.clientX, y: e.clientY });
    }

    // Check hover on data points
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const radius = Math.min(container.clientWidth, container.clientHeight) * 0.35;

    let found: GeoData | null = null;
    processedData.forEach(item => {
      const [px, py, pz] = latLngTo3D(item.coords[0], item.coords[1], radius);
      const [sx, sy, visible] = project3Dto2D(px, py, pz, rotation.y, rotation.x, container.clientWidth, container.clientHeight);
      if (visible) {
        const dist = Math.sqrt((x - sx) ** 2 + (y - sy) ** 2);
        if (dist < 20) {
          found = item;
        }
      }
    });
    setHoveredCountry(found);
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleMouseLeave = () => {
    setIsDragging(false);
    setHoveredCountry(null);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="relative w-full h-full cursor-grab active:cursor-grabbing select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseLeave}
    >
      <canvas ref={canvasRef} className="w-full h-full" />

      {/* Tooltip */}
      {hoveredCountry && (
        <div
          className="absolute bg-gray-800 text-white px-3 py-2 rounded-lg shadow-lg text-sm pointer-events-none z-10"
          style={{
            left: mousePos.x - (containerRef.current?.getBoundingClientRect().left || 0) + 10,
            top: mousePos.y - (containerRef.current?.getBoundingClientRect().top || 0) + 10
          }}
        >
          <div className="font-semibold flex items-center gap-2">
            <span className="text-lg">
              {hoveredCountry.country_code
                .toUpperCase()
                .split('')
                .map(char => String.fromCodePoint(127397 + char.charCodeAt(0)))
                .join('')}
            </span>
            {hoveredCountry.country}
          </div>
          <div className="text-blue-300">{hoveredCountry.count.toLocaleString()} requests</div>
          <div className="text-gray-400">{hoveredCountry.percentage.toFixed(1)}% of total</div>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-2 right-2 bg-gray-800/80 rounded-lg p-2 text-xs text-white">
        <div className="font-medium mb-1">Traffic by Country</div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-blue-400"></div>
          <span>Low</span>
          <div className="w-3 h-3 rounded-full bg-blue-600"></div>
          <span>High</span>
        </div>
      </div>
    </div>
  );
}

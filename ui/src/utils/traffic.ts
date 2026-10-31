import type { TrafficPoint } from '../api/traffic'

export type TrafficChartPoint = TrafficPoint & { time: number }

export function formatBytes(value: number, locale?: string): string {
  if (!Number.isFinite(value)) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const size = Math.max(0, value)
  const index = size > 0 ? Math.max(0, Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1)) : 0
  return `${(size / 1024 ** index).toLocaleString(locale, { maximumFractionDigits: 2 })} ${units[index]}`
}

// UTC-aligned buckets retain idle periods and partial buckets at both edges.
// A numeric timestamp lets the chart preserve elapsed time between samples.
export function fillTrafficBuckets(points: TrafficPoint[], start: string, end: string, seconds: number): TrafficChartPoint[] {
  const step = seconds * 1000
  const first = Math.floor(Date.parse(start) / step) * step
  const last = Math.floor((Date.parse(end) - 1) / step) * step
  const byTime = new Map(points.map(point => [Date.parse(point.timestamp), point]))
  return Array.from({ length: Math.max(0, Math.floor((last - first) / step) + 1) }, (_, i) => {
    const time = first + i * step
    const point = byTime.get(time)
    return { time, timestamp: new Date(time).toISOString(), bytes: point?.bytes ?? 0, requests: point?.requests ?? 0 }
  })
}

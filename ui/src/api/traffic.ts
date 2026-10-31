import { apiGet, getAuthHeaders, handleResponse } from './client'

export interface TrafficHost {
  id: string
  domain: string
  bytes: number
  requests: number
  percentage: number
}

export interface TrafficSummary {
  start: string
  end: string
  bytes: number
  requests: number
  hosts: TrafficHost[]
  source: string
}

export interface TrafficPoint {
  timestamp: string
  bytes: number
  requests: number
}

export interface TrafficSeries {
  points: TrafficPoint[]
  resolution: string
}

export interface RealtimeTraffic extends TrafficSeries {
  bytes_per_second: number
  requests_per_second: number
  interval_seconds: number
  updated_at: string
}

function params(start: string, end: string, hostID?: string): string {
  const query = new URLSearchParams({ start, end })
  if (hostID) query.set('proxy_host_id', hostID)
  return query.toString()
}

export const getTrafficSummary = (start: string, end: string) =>
  apiGet<TrafficSummary>(`/api/v1/traffic/summary?${params(start, end)}`)

export const getTrafficSeries = (start: string, end: string, hostID = '') =>
  apiGet<TrafficSeries>(`/api/v1/traffic/timeseries?${params(start, end, hostID)}`)

export const getRealtimeTraffic = (hostID = '') => {
  const query = new URLSearchParams()
  if (hostID) query.set('proxy_host_id', hostID)
  return apiGet<RealtimeTraffic>(`/api/v1/traffic/realtime?${query}`)
}

export async function downloadTrafficCSV(start: string, end: string): Promise<void> {
  const response = await fetch(`/api/v1/traffic/export?${params(start, end)}`, {
    headers: getAuthHeaders(),
  })
  if (!response.ok) {
    await handleResponse(response)
    return
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `npg-traffic-${start.slice(0, 10)}-${end.slice(0, 10)}.csv`
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000)
}

import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import {
  downloadTrafficCSV, getRealtimeTraffic, getTrafficSeries, getTrafficSummary,
} from '../api/traffic'
import { fillTrafficBuckets, formatBytes, type TrafficChartPoint } from '../utils/traffic'

type Period = 'hour' | 'day' | 'week' | 'month' | 'custom'
const PERIOD_HOURS: Record<Exclude<Period, 'custom'>, number> = {
  hour: 1, day: 24, week: 168, month: 720,
}

function localInput(date: Date): string {
  const offset = date.getTimezoneOffset() * 60_000
  return new Date(date.getTime() - offset).toISOString().slice(0, 16)
}

function formatCount(value: number): string {
  return value.toLocaleString(undefined, { maximumFractionDigits: 2 })
}

const panel = 'rounded-xl border border-slate-200 bg-white p-4 sm:p-5 dark:border-slate-700 dark:bg-slate-800'
const field = 'rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-100'

export default function TrafficPage() {
  const { t, i18n } = useTranslation('traffic')
  const [period, setPeriod] = useState<Period>('day')
  const [anchor, setAnchor] = useState(() => Date.now())
  const [customStart, setCustomStart] = useState(() => localInput(new Date(Date.now() - 24 * 3600_000)))
  const [customEnd, setCustomEnd] = useState(() => localInput(new Date()))
  const [appliedCustom, setAppliedCustom] = useState<[string, string] | null>(null)
  const [customError, setCustomError] = useState(false)
  const [selectedHost, setSelectedHost] = useState('')
  const [exportError, setExportError] = useState('')
  const [isExporting, setIsExporting] = useState(false)

  useEffect(() => {
    const id = window.setInterval(() => setAnchor(Date.now()), 60_000)
    return () => window.clearInterval(id)
  }, [])

  const range = useMemo(() => {
    if (period === 'custom') {
      if (!appliedCustom) return null
      return { start: appliedCustom[0], end: appliedCustom[1] }
    }
    return {
      start: new Date(anchor - PERIOD_HOURS[period] * 3600_000).toISOString(),
      end: new Date(anchor).toISOString(),
    }
  }, [period, appliedCustom, anchor])

  const summary = useQuery({
    queryKey: ['traffic', 'summary', range?.start, range?.end],
    queryFn: () => getTrafficSummary(range!.start, range!.end),
    enabled: !!range,
    staleTime: 30_000,
  })
  const history = useQuery({
    queryKey: ['traffic', 'series', range?.start, range?.end, selectedHost],
    queryFn: () => getTrafficSeries(range!.start, range!.end, selectedHost),
    enabled: !!range,
    staleTime: 30_000,
  })
  const live = useQuery({
    queryKey: ['traffic', 'realtime', selectedHost],
    queryFn: () => getRealtimeTraffic(selectedHost),
    refetchInterval: 10_000,
  })

  const locale = i18n.resolvedLanguage === 'en' ? 'en-US' : 'ko-KR'
  const timeLabel = (time: string | number, withDate = false) =>
    new Date(time).toLocaleString(locale, withDate
      ? { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }
      : { hour: '2-digit', minute: '2-digit', second: '2-digit' })

  const labelFor = (value: string) => value.toLowerCase() === 'unclassified' ? t('unclassified') : value
  const hostOptions = summary.data?.hosts ?? []
  const selectedLabel = selectedHost
    ? labelFor(hostOptions.find(h => h.id === selectedHost)?.domain ?? selectedHost)
    : t('allHosts')
  const selectedTotals = selectedHost
    ? hostOptions.find(h => h.id === selectedHost)
    : summary.data
  const livePoints = live.data ? fillTrafficBuckets(live.data.points,
    new Date(Date.parse(live.data.updated_at) - 180_000).toISOString(), live.data.updated_at, 10) : []
  const historicalPoints = useMemo(() => {
    if (!range || !history.data?.points.length) return []
    const seconds = history.data.resolution === 'day' ? 86400 : history.data.resolution === 'hour' ? 3600 : 300
    return fillTrafficBuckets(history.data.points, range.start, range.end, seconds)
  }, [range, history.data])
  const showDates = period === 'week' || period === 'month' || period === 'custom'

  const onApply = () => {
    const from = new Date(customStart).getTime()
    const to = new Date(customEnd).getTime()
    if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to ||
        to > Date.now() + 60_000 || to - from > 90 * 86400_000 ||
        from < Date.now() - 90 * 86400_000) {
      setAppliedCustom(null)
      setCustomError(true)
      return
    }
    setCustomError(false)
    setAppliedCustom([new Date(from).toISOString(), new Date(to).toISOString()])
  }

  const onExport = async () => {
    if (!range || isExporting) return
    setExportError('')
    setIsExporting(true)
    try {
      await downloadTrafficCSV(range.start, range.end)
    } catch {
      setExportError(t('exportFailed'))
    } finally {
      setIsExporting(false)
    }
  }

  const chart = (data: TrafficChartPoint[], key: 'bytes' | 'requests', dates: boolean, scope: 'live' | 'history') => (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart data={data} margin={{ top: 12, right: 10, left: 6, bottom: 0 }}>
        <defs>
          <linearGradient id={`traffic-gradient-${scope}-${key}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={key === 'bytes' ? '#0ea5e9' : '#8b5cf6'} stopOpacity={0.35} />
            <stop offset="95%" stopColor={key === 'bytes' ? '#0ea5e9' : '#8b5cf6'} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
        <XAxis dataKey="time" type="number" scale="time" domain={['dataMin', 'dataMax']} tickFormatter={v => timeLabel(Number(v), dates)} tick={{ fontSize: 11 }} minTickGap={30} />
        <YAxis width={64} tick={{ fontSize: 11 }} tickFormatter={v => key === 'bytes' ? formatBytes(v) : formatCount(v)} />
        <Tooltip labelFormatter={v => timeLabel(Number(v), true)} formatter={value => [key === 'bytes' ? formatBytes(Number(value)) : formatCount(Number(value)), t(key)]} />
        <Area type="monotone" dataKey={key} name={t(key)} stroke={key === 'bytes' ? '#0ea5e9' : '#8b5cf6'} fill={`url(#traffic-gradient-${scope}-${key})`} strokeWidth={2} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )

  return (
    <div className="space-y-5 text-slate-900 dark:text-slate-100">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-2xl font-bold">{t('title')}</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('description')}</p>
        </div>
        <button onClick={onExport} disabled={!range || isExporting} className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white hover:bg-primary-700 disabled:opacity-50">
          {t('export')}
        </button>
      </div>
      <p className="rounded-lg bg-sky-50 px-4 py-3 text-xs leading-5 text-sky-900 dark:bg-sky-900/20 dark:text-sky-200">{t('measurement')}</p>
      {exportError && <p role="alert" className="text-sm text-red-600">{exportError}</p>}

      <section className={panel} aria-label={t('period')}>
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-sm font-semibold">{t('period')}</span>
          <div className="flex flex-wrap gap-1" role="group" aria-label={t('period')}>
            {(['hour', 'day', 'week', 'month', 'custom'] as const).map(p => (
              <button key={p} onClick={() => setPeriod(p)} aria-pressed={period === p}
                className={`rounded-lg px-3 py-2 text-sm ${period === p ? 'bg-primary-600 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-200'}`}>
                {t(p)}
              </button>
            ))}
          </div>
        </div>
        {period === 'custom' && (
          <div className="mt-4 flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1 text-xs">{t('start')}<input className={field} type="datetime-local" value={customStart} onChange={e => { setCustomStart(e.target.value); setCustomError(false) }} /></label>
            <label className="flex flex-col gap-1 text-xs">{t('end')}<input className={field} type="datetime-local" value={customEnd} onChange={e => { setCustomEnd(e.target.value); setCustomError(false) }} /></label>
            <button className="rounded-lg bg-primary-600 px-4 py-2 text-sm text-white" onClick={onApply}>{t('apply')}</button>
            {customError ? <span role="alert" className="text-sm text-red-600">{t('invalidRange')}</span>
              : !range && <span role="status" className="text-sm text-slate-500 dark:text-slate-400">{t('customPrompt')}</span>}
          </div>
        )}
        <label className="mt-4 flex flex-wrap items-center gap-2 text-sm">
          <span className="font-semibold">{t('host')}</span>
          <select className={`${field} max-w-full`} value={selectedHost} onChange={e => setSelectedHost(e.target.value)}>
            <option value="">{t('allHosts')}</option>
            {hostOptions.map(h => <option key={h.id} value={h.id}>{labelFor(h.domain)}</option>)}
          </select>
        </label>
      </section>

      {summary.isError && <div role="alert" className={`${panel} text-red-600`}>{t('error')} <button className="underline" onClick={() => void summary.refetch()}>{t('retry')}</button></div>}
      {summary.isPending && range && <p role="status" className="text-sm text-slate-500">{t('loading')}</p>}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {([
          [t('totalBytes'), selectedTotals ? formatBytes(selectedTotals.bytes) : '—'],
          [t('totalRequests'), selectedTotals ? formatCount(selectedTotals.requests) : '—'],
          [t('liveRate'), live.data ? `${formatBytes(live.data.bytes_per_second)}/s` : '—'],
          [t('liveRequests'), live.data ? formatCount(live.data.requests_per_second) : '—'],
        ] as const).map(([label, value]) => (
          <div key={label} className={panel}><div className="text-xs text-slate-500 dark:text-slate-400">{label}{selectedHost ? ` · ${selectedLabel}` : ''}</div><div className="mt-2 text-2xl font-semibold tabular-nums">{value}</div></div>
        ))}
      </div>

      <section className={panel}>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><h3 className="text-lg font-semibold">{t('liveTitle')} · {selectedLabel}</h3><span className="text-xs text-slate-500">{t('liveHint')}</span></div>
        {live.isError ? <p role="alert" className="text-red-600">{t('error')} <button className="underline" onClick={() => void live.refetch()}>{t('retry')}</button></p>
          : live.isPending ? <p role="status">{t('loading')}</p>
          : <div className="grid gap-4 lg:grid-cols-2"><div><h4 className="mb-2 text-sm font-medium">{t('bytes')}</h4>{chart(livePoints, 'bytes', false, 'live')}</div><div><h4 className="mb-2 text-sm font-medium">{t('requests')}</h4>{chart(livePoints, 'requests', false, 'live')}</div></div>}
        {live.data && <p className="text-right text-xs text-slate-500">{t('updated')}: {timeLabel(live.data.updated_at, true)}</p>}
      </section>

      <section className={panel}>
        <h3 className="mb-3 text-lg font-semibold">{t('historyTitle')} · {selectedLabel}</h3>
        {history.isError ? <p role="alert" className="text-red-600">{t('error')} <button className="underline" onClick={() => void history.refetch()}>{t('retry')}</button></p>
          : !range ? <p role="status">{t('customPrompt')}</p>
          : history.isPending ? <p role="status">{t('loading')}</p>
          : historicalPoints.length === 0 ? <p className="text-sm text-slate-500">{t('empty')}</p>
          : <div className="grid gap-4 lg:grid-cols-2"><div><h4 className="mb-2 text-sm font-medium">{t('bytes')}</h4>{chart(historicalPoints, 'bytes', showDates, 'history')}</div><div><h4 className="mb-2 text-sm font-medium">{t('requests')}</h4>{chart(historicalPoints, 'requests', showDates, 'history')}</div></div>}
      </section>

      <section className={panel}>
        <h3 className="mb-3 text-lg font-semibold">{t('compareTitle')}</h3>
        {(summary.data?.hosts.length ?? 0) === 0 ? <p className="text-sm text-slate-500">{t('empty')}</p> : (
          <ResponsiveContainer width="100%" height={Math.max(180, Math.min(12, hostOptions.length) * 35)}>
            <BarChart data={hostOptions.slice(0, 12).map(h => ({ ...h, label: labelFor(h.domain) }))} layout="vertical" margin={{ left: 4, right: 12 }}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
              <XAxis type="number" tickFormatter={v => formatBytes(Number(v))} tick={{ fontSize: 11 }} />
              <YAxis dataKey="label" type="category" width={150} tick={{ fontSize: 11 }} />
              <Tooltip formatter={value => [formatBytes(Number(value)), t('bytes')]} />
              <Bar dataKey="bytes" fill="#0ea5e9" radius={[0, 4, 4, 0]} onClick={data => { if (data?.id) setSelectedHost(String(data.id)) }} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </section>

      <section className={panel}>
        <h3 className="mb-3 text-lg font-semibold">{t('hostTitle')}</h3>
        {hostOptions.some(h => h.id === 'unclassified') && (
          <p className="mb-3 text-xs leading-5 text-amber-800 dark:text-amber-300">{t('unclassifiedHint')}</p>
        )}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-700 dark:text-slate-400"><tr>
              <th scope="col" className="py-3 pr-4">{t('host')}</th>
              <th scope="col" className="px-3 py-3 text-right">{t('bytes')}</th>
              <th scope="col" className="px-3 py-3 text-right">{t('requests')}</th>
              <th scope="col" className="pl-3 py-3 text-right">{t('share')}</th>
            </tr></thead>
            <tbody>{hostOptions.map(h => <tr key={h.id} className={`border-b border-slate-100 dark:border-slate-700/50 ${selectedHost === h.id ? 'bg-sky-50 dark:bg-sky-900/20' : ''}`}>
              <td className="py-3 pr-4"><button className="max-w-xs break-all text-left text-primary-600 hover:underline dark:text-primary-400" onClick={() => setSelectedHost(h.id)} aria-pressed={selectedHost === h.id}>{labelFor(h.domain)}</button></td>
              <td className="px-3 py-3 text-right tabular-nums">{formatBytes(h.bytes)}</td>
              <td className="px-3 py-3 text-right tabular-nums">{formatCount(h.requests)}</td>
              <td className="pl-3 py-3 text-right tabular-nums">{h.percentage.toFixed(1)}%</td>
            </tr>)}</tbody>
          </table>
          {!summary.isPending && hostOptions.length === 0 && <p className="py-8 text-center text-sm text-slate-500">{t('empty')}</p>}
        </div>
      </section>
    </div>
  )
}

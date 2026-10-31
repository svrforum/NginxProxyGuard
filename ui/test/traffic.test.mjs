import assert from 'node:assert/strict'
import test from 'node:test'
import { fillTrafficBuckets, formatBytes } from '../src/utils/traffic.ts'

test('fractional byte rates retain the byte unit', () => {
  assert.equal(formatBytes(0.5, 'en-US'), '0.5 B')
  assert.equal(formatBytes(0, 'en-US'), '0 B')
  assert.equal(formatBytes(1024, 'en-US'), '1 KiB')
})

test('historical traffic keeps quiet five-minute buckets between requests', () => {
  const points = fillTrafficBuckets([
    { timestamp: '2026-10-08T10:00:00Z', bytes: 10, requests: 1 },
    { timestamp: '2026-10-08T10:15:00Z', bytes: 20, requests: 2 },
  ], '2026-10-08T10:00:00Z', '2026-10-08T10:20:00Z', 300)
  assert.deepEqual(points.map(p => p.bytes), [10, 0, 0, 20])
  assert.deepEqual(points.map(p => p.requests), [1, 0, 0, 2])
  assert.equal(points[3].time - points[0].time, 15 * 60_000)
})

test('hour and day buckets use UTC and include partial edge buckets only once', () => {
  for (const seconds of [3600, 86400]) {
    const start = Date.parse('2026-10-08T00:00:00Z')
    const points = fillTrafficBuckets([], new Date(start + 1).toISOString(),
      new Date(start + seconds * 2000 + 1).toISOString(), seconds)
    assert.deepEqual(points.map(p => p.time), [start, start + seconds * 1000, start + seconds * 2000])
    assert.ok(points.every(p => p.bytes === 0 && p.requests === 0))
  }
})

test('live traffic includes both partial ends of the last three minutes', () => {
  const points = fillTrafficBuckets([], '2026-10-08T10:00:05Z', '2026-10-08T10:03:05Z', 10)
  assert.equal(points.length, 19)
  assert.equal(points[0].timestamp, '2026-10-08T10:00:00.000Z')
  assert.equal(points.at(-1).timestamp, '2026-10-08T10:03:00.000Z')
})

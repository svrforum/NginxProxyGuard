package cache

import (
	"strings"
	"sync/atomic"
	"time"

	"github.com/maypok86/otter/v2"
	"github.com/maypok86/otter/v2/stats"
)

// LocalCache is the in-process stand-in for Valkey. RedisClient uses it for
// the plain key/value caches and the API rate limiter whenever Redis is not
// connected: on an install without REDIS_URL, that is always.
//
// It is built on otter, a Go implementation of Caffeine's design (W-TinyLFU
// admission and eviction, per-entry expiry), and is bounded by weight in
// bytes rather than by entry count, because one subscription blocklist can
// outweigh every other entry put together.
//
// Values are stored as the JSON bytes Redis would hold, so a reader decodes a
// private copy and cannot mutate what the next reader sees.
type LocalCache struct {
	kv       *otter.Cache[string, localValue]
	counters *otter.Cache[string, *localCounter]
	maxEntry uint64
	budget   uint64
	rejected atomic.Uint64
}

type localValue struct {
	data []byte
	ttl  time.Duration
}

type localCounter struct {
	n   atomic.Int64
	ttl time.Duration
}

const (
	// localEntryOverhead approximates what otter and the Go runtime spend per
	// entry beyond the key and value bytes: the node with its expiry and
	// policy links, the hash table slot, and the string and slice headers.
	// It errs high so the budget is a ceiling, not an estimate.
	localEntryOverhead = 256
	// localMaxTTL caps entries written without a TTL. Redis keeps those
	// forever; here an entry nobody invalidated should not outlive a day.
	localMaxTTL = 24 * time.Hour
	// localCounterShare is the part of the budget kept for rate-limit
	// counters, so a flood of client addresses evicts other addresses'
	// counters rather than cached settings.
	localCounterShare = 8
)

// NewLocalCache returns a cache that holds at most budget bytes, or nil when
// budget is 0.
func NewLocalCache(budget uint64) *LocalCache {
	if budget == 0 {
		return nil
	}
	// (The package's own max(int64) shadows the builtin, hence the ifs.)
	counterBudget := budget / localCounterShare
	if counterBudget < 64*localEntryOverhead {
		counterBudget = 64 * localEntryOverhead
	}
	if counterBudget > budget/2 {
		counterBudget = budget / 2
	}
	kvBudget := budget - counterBudget

	lc := &LocalCache{
		budget: budget,
		// A value larger than this is not cached at all: admitting it would
		// only evict most of the cache to make room for one entry.
		maxEntry: kvBudget / 8,
	}
	lc.kv = otter.Must(&otter.Options[string, localValue]{
		MaximumWeight: kvBudget,
		Weigher: func(key string, v localValue) uint32 {
			return weight(uint64(len(key)) + uint64(cap(v.data)))
		},
		ExpiryCalculator: otter.ExpiryWritingFunc(func(e otter.Entry[string, localValue]) time.Duration {
			return e.Value.ttl
		}),
		StatsRecorder: stats.NewCounter(),
	})
	lc.counters = otter.Must(&otter.Options[string, *localCounter]{
		MaximumWeight: counterBudget,
		Weigher: func(key string, _ *localCounter) uint32 {
			return weight(uint64(len(key)))
		},
		ExpiryCalculator: otter.ExpiryCreatingFunc(func(e otter.Entry[string, *localCounter]) time.Duration {
			return e.Value.ttl
		}),
	})
	return lc
}

// weight is an entry's size in bytes plus its fixed overhead, saturated to
// the uint32 otter takes. set refuses anything near that size long before.
func weight(n uint64) uint32 {
	n += localEntryOverhead
	if n > 1<<32-1 {
		return 1<<32 - 1
	}
	return uint32(n)
}

func localTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 || ttl > localMaxTTL {
		return localMaxTTL
	}
	return ttl
}

// set stores data under key. It reports false when the value is too large to
// cache, which callers treat like any other cache write failure.
func (lc *LocalCache) set(key string, data []byte, ttl time.Duration) bool {
	if uint64(len(key))+uint64(cap(data))+localEntryOverhead > lc.maxEntry {
		lc.rejected.Add(1)
		lc.kv.Invalidate(key)
		return false
	}
	lc.kv.Set(key, localValue{data: data, ttl: localTTL(ttl)})
	return true
}

func (lc *LocalCache) get(key string) ([]byte, bool) {
	v, ok := lc.kv.GetIfPresent(key)
	if !ok {
		return nil, false
	}
	return v.data, true
}

func (lc *LocalCache) del(keys ...string) {
	for _, k := range keys {
		lc.kv.Invalidate(k)
	}
}

func (lc *LocalCache) delPrefix(prefix string) {
	var doomed []string
	for k := range lc.kv.Keys() {
		if strings.HasPrefix(k, prefix) {
			doomed = append(doomed, k)
		}
	}
	lc.del(doomed...)
}

// incr adds one to the counter under key, creating it with the given
// lifetime, and returns the new count.
func (lc *LocalCache) incr(key string, ttl time.Duration) int64 {
	c, _ := lc.counters.SetIfAbsent(key, &localCounter{ttl: ttl})
	return c.n.Add(1)
}

// flush drops everything. RedisClient calls it once Redis connects, so values
// written while it was away cannot resurface later.
func (lc *LocalCache) flush() {
	lc.kv.InvalidateAll()
	lc.counters.InvalidateAll()
}

func (lc *LocalCache) close() {
	lc.kv.StopAllGoroutines()
	lc.counters.StopAllGoroutines()
}

// LocalCacheStats is what the detailed health endpoint reports about the
// in-process cache.
type LocalCacheStats struct {
	BudgetBytes   uint64  `json:"budget_bytes"`
	WeightedBytes uint64  `json:"weighted_bytes"`
	Entries       int     `json:"entries"`
	Counters      int     `json:"rate_limit_counters"`
	HitRatio      float64 `json:"hit_ratio"`
	Evictions     uint64  `json:"evictions"`
	TooLarge      uint64  `json:"too_large"`
}

// Stats returns a snapshot of the cache's size and effectiveness.
func (lc *LocalCache) Stats() LocalCacheStats {
	s := lc.kv.Stats()
	return LocalCacheStats{
		BudgetBytes:   lc.budget,
		WeightedBytes: lc.kv.WeightedSize() + lc.counters.WeightedSize(),
		Entries:       lc.kv.EstimatedSize(),
		Counters:      lc.counters.EstimatedSize(),
		HitRatio:      s.HitRatio(),
		Evictions:     s.Evictions,
		TooLarge:      lc.rejected.Load(),
	}
}

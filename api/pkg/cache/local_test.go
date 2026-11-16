package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newLocalOnly is a client the way an install without REDIS_URL gets it.
func newLocalOnly(t *testing.T, budget uint64) *RedisClient {
	t.Helper()
	rc, err := NewRedisClient("", NewLocalCache(budget))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rc.Close() })
	return rc
}

func TestLocalCacheServesWithoutRedis(t *testing.T) {
	rc := newLocalOnly(t, 8<<20)
	ctx := context.Background()

	if rc.IsReady() {
		t.Fatal("no Redis is configured, IsReady must stay false")
	}
	if !rc.Available() || rc.Backend() != "local" || rc.RedisConfigured() {
		t.Fatalf("Available=%v Backend=%q RedisConfigured=%v", rc.Available(), rc.Backend(), rc.RedisConfigured())
	}

	type settings struct {
		Name  string
		Count int
	}
	if err := rc.SetSystemSettings(ctx, settings{Name: "a", Count: 3}); err != nil {
		t.Fatalf("SetSystemSettings: %v", err)
	}
	var got settings
	if err := rc.GetSystemSettings(ctx, &got); err != nil || got.Name != "a" || got.Count != 3 {
		t.Fatalf("GetSystemSettings = %+v, %v", got, err)
	}

	// A reader decodes its own copy: changing it must not leak to the next.
	got.Name = "mutated"
	var again settings
	_ = rc.GetSystemSettings(ctx, &again)
	if again.Name != "a" {
		t.Fatalf("cached value was mutated through a reader: %+v", again)
	}

	if err := rc.InvalidateSystemSettings(ctx); err != nil {
		t.Fatalf("InvalidateSystemSettings: %v", err)
	}
	if err := rc.GetSystemSettings(ctx, &got); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("after invalidate: %v, want ErrCacheMiss", err)
	}
}

func TestLocalCacheWithoutAnyBackend(t *testing.T) {
	rc, err := NewRedisClient("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	ctx := context.Background()
	if rc.Available() || rc.Backend() != "none" {
		t.Fatalf("Available=%v Backend=%q", rc.Available(), rc.Backend())
	}
	if err := rc.Set(ctx, "k", 1, time.Minute); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Set = %v, want ErrNotReady", err)
	}
	var v int
	if err := rc.Get(ctx, "k", &v); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Get = %v, want ErrNotReady", err)
	}
	res, err := rc.CheckAPIRateLimit(ctx, "ip", 1, time.Minute)
	if err != nil || !res.Allowed {
		t.Fatalf("CheckAPIRateLimit with no backend = %+v, %v; want allowed", res, err)
	}
}

func TestLocalCacheExpires(t *testing.T) {
	rc := newLocalOnly(t, 8<<20)
	ctx := context.Background()
	if err := rc.Set(ctx, "short", "v", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		var s string
		err := rc.Get(ctx, "short", &s)
		if errors.Is(err, ErrCacheMiss) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry with a 50ms TTL still present after 3s (err=%v)", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestLocalCachePrefixInvalidation(t *testing.T) {
	rc := newLocalOnly(t, 8<<20)
	ctx := context.Background()
	for _, h := range []string{"h1", "h2"} {
		if err := rc.SetProxyHostConfig(ctx, h, map[string]string{"id": h}); err != nil {
			t.Fatal(err)
		}
		if err := rc.SetHostExploitExclusions(ctx, h, []string{"x"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rc.SetGlobalSettings(ctx, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}

	if err := rc.InvalidateAllProxyHostConfigs(ctx); err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	for _, h := range []string{"h1", "h2"} {
		if err := rc.GetProxyHostConfig(ctx, h, &m); !errors.Is(err, ErrCacheMiss) {
			t.Fatalf("proxy host %s config survived InvalidateAll: %v", h, err)
		}
	}
	var ex []string
	if err := rc.GetHostExploitExclusions(ctx, "h1", &ex); err != nil {
		t.Fatalf("an unrelated prefix was invalidated too: %v", err)
	}
	if err := rc.InvalidateHostExploitExclusions(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if err := rc.GetHostExploitExclusions(ctx, "h1", &ex); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("h1 exclusions survived: %v", err)
	}
	if err := rc.GetHostExploitExclusions(ctx, "h2", &ex); err != nil {
		t.Fatalf("h2 exclusions went with h1: %v", err)
	}
	var g map[string]int
	if err := rc.GetGlobalSettings(ctx, &g); err != nil || g["a"] != 1 {
		t.Fatalf("global settings = %v, %v", g, err)
	}
}

// The budget is a ceiling: filling the cache far past it must leave the
// weighed size within it, and a value too big for the cache is refused
// instead of evicting everything else.
func TestLocalCacheStaysWithinBudget(t *testing.T) {
	const budget = 4 << 20
	lc := NewLocalCache(budget)
	defer lc.close()

	blob := []byte(`"` + strings.Repeat("x", 16<<10) + `"`)
	for i := 0; i < 2000; i++ { // ~32 MiB offered to a 4 MiB cache
		lc.set("k"+time.Duration(i).String(), append([]byte(nil), blob...), time.Hour)
	}
	lc.kv.CleanUp()
	st := lc.Stats()
	if st.WeightedBytes > budget {
		t.Fatalf("weighted size %d exceeds the %d budget", st.WeightedBytes, budget)
	}
	if st.Evictions == 0 {
		t.Fatal("nothing was evicted though far more than the budget was written")
	}

	huge := make([]byte, budget/4)
	if lc.set("huge", huge, time.Hour) {
		t.Fatal("a value larger than an eighth of the cache was accepted")
	}
	if _, ok := lc.get("huge"); ok {
		t.Fatal("refused value is readable")
	}
	if lc.Stats().TooLarge != 1 {
		t.Fatalf("TooLarge = %d, want 1", lc.Stats().TooLarge)
	}
}

func TestSetTooLargeReturnsErrTooLarge(t *testing.T) {
	rc := newLocalOnly(t, 4<<20)
	big := strings.Repeat("y", 1<<20)
	if err := rc.Set(context.Background(), "big", big, time.Minute); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Set of a 1 MiB value into a 4 MiB cache = %v, want ErrTooLarge", err)
	}
}

func TestLocalAPIRateLimit(t *testing.T) {
	rc := newLocalOnly(t, 8<<20)
	ctx := context.Background()
	const limit = 3
	for i := 1; i <= limit; i++ {
		res, err := rc.CheckAPIRateLimit(ctx, "api:192.0.2.1", limit, time.Minute)
		if err != nil || !res.Allowed || res.Current != int64(i) || res.Remaining != int64(limit-i) {
			t.Fatalf("request %d: %+v, %v", i, res, err)
		}
	}
	res, err := rc.CheckAPIRateLimit(ctx, "api:192.0.2.1", limit, time.Minute)
	if err != nil || res.Allowed || res.RetryAfter <= 0 {
		t.Fatalf("request over the limit: %+v, %v", res, err)
	}
	other, _ := rc.CheckAPIRateLimit(ctx, "api:192.0.2.2", limit, time.Minute)
	if !other.Allowed || other.Current != 1 {
		t.Fatalf("another address shares the counter: %+v", other)
	}
}

func TestFlushDropsLocalEntries(t *testing.T) {
	lc := NewLocalCache(8 << 20)
	defer lc.close()
	lc.set("a", []byte(`1`), time.Hour)
	lc.incr("c", time.Minute)
	lc.flush()
	if _, ok := lc.get("a"); ok {
		t.Fatal("flush left a value")
	}
	if n := lc.incr("c", time.Minute); n != 1 {
		t.Fatalf("flush left a counter: next count %d", n)
	}
}

func TestLocalCacheBudget(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	saved := memorySources
	t.Cleanup(func() { memorySources = saved })

	cases := []struct {
		name     string
		v2, v1   string
		meminfo  string
		want     uint64
		wantFrom string
	}{
		{"cgroup v2 limit", "536870912\n", "", "MemTotal:       24000000 kB\n", 16 << 20, "memory.max"},
		{"cgroup v2 unlimited falls back to MemTotal, capped", "max\n", "", "MemTotal:       24000000 kB\n", localBudgetMax, "MemTotal"},
		{"cgroup v1 limit", "", "268435456\n", "MemTotal:       24000000 kB\n", 8 << 20, "limit_in_bytes"},
		{"cgroup v1 no-limit sentinel", "", "9223372036854771712\n", "MemTotal:       2000000 kB\n", 2000000 * 1024 / 32, "MemTotal"},
		{"tiny container gets the floor", "67108864\n", "", "", localBudgetMin, "memory.max"},
		{"nothing readable", "", "", "", localBudgetUnknown, "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			memorySources.cgroupV2Max = filepath.Join(dir, "absent-v2")
			memorySources.cgroupV1Max = filepath.Join(dir, "absent-v1")
			memorySources.meminfo = filepath.Join(dir, "absent-meminfo")
			if tc.v2 != "" {
				memorySources.cgroupV2Max = write("v2-"+tc.name, tc.v2)
			}
			if tc.v1 != "" {
				memorySources.cgroupV1Max = write("v1-"+tc.name, tc.v1)
			}
			if tc.meminfo != "" {
				memorySources.meminfo = write("mi-"+tc.name, "MemFree: 1 kB\n"+tc.meminfo)
			}
			got, why := LocalCacheBudget(-1)
			if got != tc.want || !strings.Contains(why, tc.wantFrom) {
				t.Fatalf("LocalCacheBudget = %d (%s), want %d from %s", got, why, tc.want, tc.wantFrom)
			}
		})
	}

	if got, _ := LocalCacheBudget(0); got != 0 {
		t.Fatalf("NPG_LOCAL_CACHE_MAX_MB=0 gave %d, want 0 (off)", got)
	}
	if got, _ := LocalCacheBudget(10); got != 10<<20 {
		t.Fatalf("NPG_LOCAL_CACHE_MAX_MB=10 gave %d", got)
	}
	if NewLocalCache(0) != nil {
		t.Fatal("a zero budget must mean no local cache")
	}
}

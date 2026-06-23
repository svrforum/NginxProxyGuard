package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/config"
)

// UpdateInfo is the result of an update check (#190). It is DISPLAY + GUIDANCE
// only — NginxProxyGuard never updates itself (auto-update was deemed too risky:
// a container updating its own image needs Docker socket access / multi-container
// version coordination). The UI shows this and points the operator at the
// documented `docker compose pull && up -d` command.
type UpdateInfo struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      string `json:"release_url"`
	PublishedAt     string `json:"published_at"`
	CheckedAt       string `json:"checked_at"`
	CheckFailed     bool   `json:"check_failed"`
}

// UpdateChecker queries the GitHub Releases API for the latest published release
// and compares it with the running version. Results are cached to respect the
// unauthenticated GitHub rate limit (60 req/h). Dependency-free (just an HTTP
// client + cache), so it is constructed directly by its handler.
type UpdateChecker struct {
	httpClient   *http.Client
	mu           sync.Mutex
	cached       *UpdateInfo
	cachedAt     time.Time
	lastForcedAt time.Time
}

func NewUpdateChecker() *UpdateChecker {
	return &UpdateChecker{
		httpClient: &http.Client{Timeout: config.UpdateCheckTimeout},
	}
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
}

// Check returns update info. Within UpdateCheckCacheTTL the cached result is
// reused; force=true bypasses the cache (manual re-check). On fetch failure it
// degrades gracefully: CheckFailed=true plus the last known latest version (if
// any), never an error to the caller.
func (u *UpdateChecker) Check(ctx context.Context, force bool) *UpdateInfo {
	now := time.Now()

	// Cache decision under the lock, but the network call below runs WITHOUT it
	// so a slow GitHub request never blocks concurrent callers (only the brief
	// cache read/write is serialized).
	u.mu.Lock()
	if u.cached != nil {
		fresh := now.Sub(u.cachedAt) < config.UpdateCheckCacheTTL
		// Throttle forced re-checks so a caller can't loop ?force=true and burn
		// the GitHub rate limit.
		forceThrottled := force && now.Sub(u.lastForcedAt) < config.UpdateForceMinInterval
		if (!force && fresh) || forceThrottled {
			cached := u.cached
			u.mu.Unlock()
			return cached
		}
	}
	if force {
		u.lastForcedAt = now
	}
	prev := u.cached
	u.mu.Unlock()

	info := &UpdateInfo{
		CurrentVersion: config.AppVersion,
		CheckedAt:      now.UTC().Format(time.RFC3339),
	}

	tag, url, published, err := u.fetchLatest(ctx)
	if err != nil {
		info.CheckFailed = true
		// Surface the last known latest so the UI still shows something useful.
		if prev != nil && prev.LatestVersion != "" {
			info.LatestVersion = prev.LatestVersion
			info.ReleaseURL = prev.ReleaseURL
			info.PublishedAt = prev.PublishedAt
			info.UpdateAvailable = prev.UpdateAvailable
		}
		// Do not cache failures, so the next call retries the fetch.
		return info
	}

	info.LatestVersion = strings.TrimPrefix(tag, "v")
	info.ReleaseURL = url
	info.PublishedAt = published
	info.UpdateAvailable = compareVersions(info.CurrentVersion, info.LatestVersion) < 0

	u.mu.Lock()
	u.cached = info
	u.cachedAt = time.Now()
	u.mu.Unlock()
	return info
}

func (u *UpdateChecker) fetchLatest(ctx context.Context) (tag, url, published string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.GitHubLatestReleaseURL, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", "NginxProxyGuard/"+config.AppVersion)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("github releases API returned %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", "", err
	}
	if rel.TagName == "" {
		return "", "", "", fmt.Errorf("latest release has no tag_name")
	}
	return rel.TagName, rel.HTMLURL, rel.PublishedAt, nil
}

// compareVersions compares two dotted numeric versions ("2.28.4"), ignoring a
// leading "v". Returns -1 if a<b, 0 if equal, 1 if a>b. Missing/non-numeric
// parts count as 0, so "2.28" < "2.28.1".
func compareVersions(a, b string) int {
	pa := strings.Split(strings.TrimPrefix(a, "v"), ".")
	pb := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimSpace(pa[i]))
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(strings.TrimSpace(pb[i]))
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

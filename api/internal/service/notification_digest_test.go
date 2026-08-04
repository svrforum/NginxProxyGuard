package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

type fakeDigestSource struct {
	overview  *repository.DigestOverview
	resources *repository.DigestResources
	ips       []model.IPStat
	byReason  map[string]int64
	total     int64
}

func (f *fakeDigestSource) GetDigestResources(context.Context) (*repository.DigestResources, error) {
	return f.resources, nil
}

func (f *fakeDigestSource) GetTopBlockedIPs(context.Context, time.Time, int) ([]model.IPStat, error) {
	return f.ips, nil
}
func (f *fakeDigestSource) GetBlockBreakdown(context.Context, time.Time) (map[string]int64, int64, error) {
	return f.byReason, f.total, nil
}

func (f *fakeDigestSource) GetDigestOverview(context.Context, time.Time) (*repository.DigestOverview, error) {
	return f.overview, nil
}

func TestDigestRendersCounts(t *testing.T) {
	s := &NotificationDigestService{dash: &fakeDigestSource{
		total:    142,
		byReason: map[string]int64{"waf": 100, "bot_filter": 30, "rate_limit": 12},
		ips:      []model.IPStat{{IP: "192.0.2.5", Count: 80}, {IP: "198.51.100.9", Count: 22}},
	}}
	d, err := s.Build(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	text := d.Text("en", "")
	if !strings.Contains(text, "Blocked requests: 142") {
		t.Fatalf("total missing:\n%s", text)
	}
	// Reasons are ordered by weight, so the biggest problem is read first.
	waf := strings.Index(text, "waf: 100")
	bot := strings.Index(text, "bot_filter: 30")
	if waf < 0 || bot < 0 || waf > bot {
		t.Fatalf("reasons not ordered by count:\n%s", text)
	}
	if !strings.Contains(text, "192.0.2.5 — 80") {
		t.Fatalf("top blocked address missing:\n%s", text)
	}
}

func TestDigestSaysNothingHappened(t *testing.T) {
	s := &NotificationDigestService{dash: &fakeDigestSource{byReason: map[string]int64{}}}
	d, _ := s.Build(context.Background(), time.Now())
	if !strings.Contains(d.Text("en", ""), "Nothing was blocked") {
		t.Fatalf("a quiet day should say so:\n%s", d.Text("en", ""))
	}
}

// Edge triggering means a long-running failure is announced once. The digest is
// the other half of that bargain: it keeps the failure visible afterwards.
func TestDigestKeepsOutstandingFailuresVisible(t *testing.T) {
	s := &NotificationDigestService{
		dash: &fakeDigestSource{byReason: map[string]int64{}},
		state: &fakeFailures{out: []model.NotificationState{
			{EventKey: "cert.renewal_failed", Subject: "cert-1", Since: time.Now().Add(-72 * time.Hour)},
		}},
	}
	d, _ := s.Build(context.Background(), time.Now())
	text := d.Text("en", "")
	// The readable title, not the raw key — the digest is read by a person.
	if !strings.Contains(text, "Still failing") || !strings.Contains(text, "certificate renewal failed") {
		t.Fatalf("outstanding failure missing:\n%s", text)
	}

	// The same summary in Korean, because the channel decides the language.
	ko := d.Text("ko", "")
	if !strings.Contains(ko, "아직 복구되지 않음") || !strings.Contains(ko, "인증서 갱신 실패") {
		t.Fatalf("Korean digest not localised:\n%s", ko)
	}
}

// A channel configured in Korean must not receive English prose.
func TestMessagesFollowTheChannelLanguage(t *testing.T) {
	msg := SampleMessage("ko", "cert.renewal_failed")
	if !strings.Contains(msg.Text, "인증서 갱신 실패") {
		t.Fatalf("Korean sample not localised:\n%s", msg.Text)
	}
	if strings.Contains(msg.Text, "certificate renewal failed") {
		t.Fatalf("English leaked into a Korean message:\n%s", msg.Text)
	}
	// Field labels too — "host:" in an otherwise Korean message reads as a bug.
	if !strings.Contains(msg.Text, "호스트") {
		t.Fatalf("field labels not localised:\n%s", msg.Text)
	}

	en := SampleMessage("en", "cert.renewal_failed")
	if !strings.Contains(en.Text, "certificate renewal failed") {
		t.Fatalf("English sample broken:\n%s", en.Text)
	}
	// An unknown language falls back rather than rendering keys.
	if fb := SampleMessage("fr", "cert.renewal_failed"); !strings.Contains(fb.Text, "certificate renewal failed") {
		t.Fatalf("unknown language did not fall back:\n%s", fb.Text)
	}
}

// The digest crosses the network, so it must never carry a visitor's path,
// user-agent or raw log line.
func TestDigestCarriesNoVisitorData(t *testing.T) {
	s := &NotificationDigestService{dash: &fakeDigestSource{
		total: 5, byReason: map[string]int64{"waf": 5},
		ips: []model.IPStat{{IP: "192.0.2.5", Count: 5}},
	}}
	d, _ := s.Build(context.Background(), time.Now())
	text := strings.ToLower(d.Text("en", ""))
	for _, banned := range []string{"user-agent", "user_agent", "mozilla", "raw_log", "request_uri", "cookie", "authorization"} {
		if strings.Contains(text, banned) {
			t.Errorf("digest leaked %q:\n%s", banned, d.Text("en", ""))
		}
	}
}

// Resource usage is the half of the summary an operator acts on before
// anything is broken — a disk at 95% is the warning that the logs are about to
// stop nginx.
func TestDigestReportsResourceUsage(t *testing.T) {
	now := time.Now()
	s := &NotificationDigestService{dash: &fakeDigestSource{
		byReason: map[string]int64{},
		resources: &repository.DigestResources{
			RecordedAt:    now.Add(-30 * time.Second),
			CPUUsage:      23.4,
			MemoryUsage:   55.0,
			DiskUsage:     85.0,
			MemoryTotal:   16 * 1024 * 1024 * 1024,
			MemoryUsed:    9 * 1024 * 1024 * 1024,
			DiskTotal:     500 * 1024 * 1024 * 1024,
			DiskUsed:      425 * 1024 * 1024 * 1024,
			UptimeSeconds: 12*86400 + 4*3600,
			DatabaseBytes: 775550643,
		},
	}}
	d, err := s.Build(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}

	en := d.Text("en", "")
	for _, want := range []string{"CPU: 23%", "Memory: 9.0 GB / 16.0 GB (55%)", "Disk: 425.0 GB / 500.0 GB (85%)", "Database: 739.6 MB", "Uptime: 12d 4h"} {
		if !strings.Contains(en, want) {
			t.Errorf("missing %q:\n%s", want, en)
		}
	}

	ko := d.Text("ko", "")
	for _, want := range []string{"메모리: 9.0 GB / 16.0 GB (55%)", "디스크:", "데이터베이스: 739.6 MB", "가동 시간: 12일 4시간"} {
		if !strings.Contains(ko, want) {
			t.Errorf("Korean digest missing %q:\n%s", want, ko)
		}
	}
}

// A stopped stats collector must not have the digest quote yesterday's CPU
// figure as if it were current. The database size is still true, so it stays.
func TestDigestDropsAStaleResourceSample(t *testing.T) {
	now := time.Now()
	s := &NotificationDigestService{dash: &fakeDigestSource{
		byReason: map[string]int64{},
		resources: &repository.DigestResources{
			RecordedAt:    now.Add(-6 * time.Hour),
			CPUUsage:      23.4,
			MemoryTotal:   16 * 1024 * 1024 * 1024,
			MemoryUsed:    9 * 1024 * 1024 * 1024,
			UptimeSeconds: 3600,
			DatabaseBytes: 775550643,
		},
	}}
	d, _ := s.Build(context.Background(), now)
	text := d.Text("en", "")
	if strings.Contains(text, "CPU") || strings.Contains(text, "Memory") || strings.Contains(text, "Uptime") {
		t.Errorf("stale host sample was quoted:\n%s", text)
	}
	if !strings.Contains(text, "Database: 739.6 MB") {
		t.Errorf("database size should survive a stale host sample:\n%s", text)
	}
}

// A fresh install has no sample at all. The block must vanish rather than
// print a row of zeroes, which reads as a broken digest.
func TestDigestOmitsResourcesOnAFreshInstall(t *testing.T) {
	s := &NotificationDigestService{dash: &fakeDigestSource{byReason: map[string]int64{}}}
	d, _ := s.Build(context.Background(), time.Now())
	text := d.Text("en", "")
	for _, absent := range []string{"CPU", "Memory", "Disk", "Database", "Uptime", "0%"} {
		if strings.Contains(text, absent) {
			t.Errorf("empty resource block leaked %q:\n%s", absent, text)
		}
	}
}

func TestUptimeReadsCoarsestUnitFirst(t *testing.T) {
	cases := []struct {
		seconds int64
		en, ko  string
	}{
		{12*86400 + 4*3600, "12d 4h", "12일 4시간"},
		{4*3600 + 30*60, "4h 30m", "4시간 30분"},
		{90, "1m", "1분"},
	}
	for _, c := range cases {
		if got := formatUptime("en", c.seconds); got != c.en {
			t.Errorf("formatUptime(en, %d) = %q, want %q", c.seconds, got, c.en)
		}
		if got := formatUptime("ko", c.seconds); got != c.ko {
			t.Errorf("formatUptime(ko, %d) = %q, want %q", c.seconds, got, c.ko)
		}
	}
}

// Every string the digest can print must exist in both languages. The earlier
// leak — a dashboard link that arrived as "digest.openDashboard: https://…" —
// was a key present in one table and missing from the other, which tr() hides
// by falling back to English before falling back to the key.
func TestNotificationStringsHaveKoAndEnParity(t *testing.T) {
	for key := range notificationStrings[LangEnglish] {
		if v, ok := notificationStrings[LangKorean][key]; !ok || v == "" {
			t.Errorf("%q exists in English but not in Korean — it would silently arrive in English", key)
		}
	}
	for key := range notificationStrings[LangKorean] {
		if v, ok := notificationStrings[LangEnglish][key]; !ok || v == "" {
			t.Errorf("%q exists in Korean but not in English", key)
		}
	}
}

type fakeFailures struct{ out []model.NotificationState }

func (f *fakeFailures) OutstandingFailures(context.Context) ([]model.NotificationState, error) {
	return f.out, nil
}

// A missing translation used to leak the lookup key straight into a message —
// the dashboard link arrived as "digest.openDashboard: https://…". Every key the
// digest and the formatter use must resolve in both languages.
func TestNoTranslationKeyLeaksIntoMessages(t *testing.T) {
	keys := []string{
		"digest.title", "digest.quiet", "digest.blocked", "digest.topIPs",
		"digest.certs", "digest.failing", "digest.since", "digest.openDashboard",
		"digest.requests", "digest.hosts", "digest.redirects", "digest.certificates",
		"digest.bannedActive",
		"digest.cpu", "digest.memory", "digest.disk", "digest.database", "digest.uptime",
		"unit.day", "unit.hour", "unit.minute",
		"severity.error", "severity.warning", "severity.info", "severity.resolved",
		"footer.signature",
	}
	for _, lang := range []string{"en", "ko"} {
		for _, k := range keys {
			if got := tr(lang, k); got == k {
				t.Errorf("%s/%s is untranslated and would print the key", lang, k)
			}
		}
	}
	// And the rendered digest must contain no dotted lookup keys at all. Every
	// optional block is populated here on purpose: a nil-guarded section that
	// never renders is a section this test cannot check.
	d := &Digest{
		ByReason:      map[string]int64{"waf": 3},
		BlockedTotal:  3,
		Overview:      &repository.DigestOverview{ProxyHostsTotal: 2, ProxyHostsEnabled: 2, RedirectsEnabled: 1, CertificatesTotal: 1, RequestsTotal: 10},
		Resources:     &repository.DigestResources{RecordedAt: time.Now(), CPUUsage: 4, MemoryTotal: 1 << 34, MemoryUsed: 1 << 33, DiskTotal: 1 << 39, DiskUsed: 1 << 38, UptimeSeconds: 90061, DatabaseBytes: 1 << 30},
		TopBlockedIPs: []model.IPStat{{IP: "192.0.2.5", Count: 3}},
		ExpiringCerts: []string{"app.example.com (5d)"},
		Outstanding:   []model.NotificationState{{EventKey: "cert.renewal_failed", Subject: "app.example.com", Since: time.Now().Add(-time.Hour)}},
	}
	for _, lang := range []string{"en", "ko"} {
		text := d.Text(lang, "https://npg.example.com")
		for _, k := range keys {
			if strings.Contains(text, k) {
				t.Errorf("%s digest leaked the key %q:\n%s", lang, k, text)
			}
		}
	}
}

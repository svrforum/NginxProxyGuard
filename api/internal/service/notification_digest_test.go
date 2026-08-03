package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

type fakeDigestSource struct {
	ips      []model.IPStat
	byReason map[string]int64
	total    int64
}

func (f *fakeDigestSource) GetTopBlockedIPs(context.Context, time.Time, int) ([]model.IPStat, error) {
	return f.ips, nil
}
func (f *fakeDigestSource) GetBlockBreakdown(context.Context, time.Time) (map[string]int64, int64, error) {
	return f.byReason, f.total, nil
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
	text := d.Text("en")
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
	if !strings.Contains(d.Text("en"), "Nothing was blocked") {
		t.Fatalf("a quiet day should say so:\n%s", d.Text("en"))
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
	text := d.Text("en")
	// The readable title, not the raw key — the digest is read by a person.
	if !strings.Contains(text, "Still failing") || !strings.Contains(text, "certificate renewal failed") {
		t.Fatalf("outstanding failure missing:\n%s", text)
	}

	// The same summary in Korean, because the channel decides the language.
	ko := d.Text("ko")
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
	text := strings.ToLower(d.Text("en"))
	for _, banned := range []string{"user-agent", "user_agent", "mozilla", "raw_log", "request_uri", "cookie", "authorization"} {
		if strings.Contains(text, banned) {
			t.Errorf("digest leaked %q:\n%s", banned, d.Text("en"))
		}
	}
}

type fakeFailures struct{ out []model.NotificationState }

func (f *fakeFailures) OutstandingFailures(context.Context) ([]model.NotificationState, error) {
	return f.out, nil
}

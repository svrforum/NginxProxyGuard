package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Getting this table wrong is how an operator's IP gets banned: Discord counts
// 401/403/429 toward a limit of 10,000 invalid requests per 10 minutes enforced
// by a Cloudflare IP ban, and documents that retrying a deleted (404) webhook
// causes a temporary restriction.
func TestClassifyResponse(t *testing.T) {
	for _, tt := range []struct {
		status int
		want   Outcome
		name   string
	}{
		{200, OutcomeSent, "ok"},
		{204, OutcomeSent, "discord success"},
		{299, OutcomeSent, "any 2xx"},
		{429, OutcomeRetry, "throttled"},
		{500, OutcomeRetry, "server error"},
		{502, OutcomeRetry, "bad gateway"},
		{503, OutcomeRetry, "unavailable"},
		{404, OutcomeFailed, "a deleted webhook must never be retried"},
		{401, OutcomeFailed, "bad credential"},
		{403, OutcomeFailed, "forbidden"},
		{400, OutcomeFailed, "malformed"},
		{301, OutcomeFailed, "unexpected redirect"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := classifyResponse(tt.status, "")
			if got != tt.want {
				t.Fatalf("status %d: got %v want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestClassifyHonoursRetryAfter(t *testing.T) {
	if _, d := classifyResponse(429, "7"); d != 7*time.Second {
		t.Fatalf("got %v, want 7s", d)
	}
	// A missing or unparseable header must not become a zero-delay hot loop.
	if _, d := classifyResponse(429, ""); d <= 0 {
		t.Fatalf("got %v, want a positive default", d)
	}
	if _, d := classifyResponse(429, "not-a-number"); d <= 0 {
		t.Fatalf("got %v, want a positive default", d)
	}
	// An absurd value must not park the queue for a day.
	if _, d := classifyResponse(429, "999999"); d > time.Hour {
		t.Fatalf("got %v, want it clamped", d)
	}
}

func TestBackoffSchedule(t *testing.T) {
	want := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := backoffFor(i + 1); got != w {
			t.Errorf("attempt %d: got %v want %v", i+1, got, w)
		}
	}
	if !isExhausted(4) {
		t.Error("the fourth attempt should exhaust — an unreachable receiver must not be retried forever")
	}
	if isExhausted(3) {
		t.Error("three attempts is not yet exhausted")
	}
}

func TestWebhookAdapterBuildsTheEnvelope(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content type = %q", ct)
		}
		if r.Header.Get("X-Token") != "s3cret" {
			t.Errorf("custom header not sent")
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ch := &model.NotificationChannel{
		Type:               model.NotificationTypeWebhook,
		AllowPrivateTarget: true, // httptest listens on loopback
		Config:             map[string]string{"url": srv.URL, "header_X-Token": "s3cret"},
	}
	out, _, err := newWebhookAdapter().Send(context.Background(), ch,
		model.RenderedMessage{Event: "ip.banned", Text: "banned 192.0.2.5",
			Severity: "warning", Fields: map[string]string{"ip": "192.0.2.5"}})
	if err != nil || out != OutcomeSent {
		t.Fatalf("out=%v err=%v", out, err)
	}
	if got["event"] != "ip.banned" || got["text"] != "banned 192.0.2.5" || got["severity"] != "warning" {
		t.Fatalf("envelope = %#v", got)
	}
	fields, _ := got["fields"].(map[string]any)
	if fields["ip"] != "192.0.2.5" {
		t.Fatalf("fields = %#v", got["fields"])
	}
}

// DNS can be re-pointed after a channel is saved, so the destination is checked
// again at send time rather than trusted from validation.
func TestWebhookAdapterRevalidatesTheTarget(t *testing.T) {
	ch := &model.NotificationChannel{
		Type:               model.NotificationTypeWebhook,
		AllowPrivateTarget: false,
		Config:             map[string]string{"url": "http://169.254.169.254/latest/meta-data/"},
	}
	out, _, err := newWebhookAdapter().Send(context.Background(), ch, model.RenderedMessage{Text: "hi"})
	if err == nil {
		t.Fatal("expected the metadata address to be refused at send time")
	}
	if out != OutcomeFailed {
		t.Fatalf("out = %v, want failed — a bad target is not worth retrying", out)
	}
}

func TestWebhookAdapterClassifiesServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	ch := &model.NotificationChannel{
		Type: model.NotificationTypeWebhook, AllowPrivateTarget: true,
		Config: map[string]string{"url": srv.URL},
	}
	out, _, _ := newWebhookAdapter().Send(context.Background(), ch, model.RenderedMessage{Text: "hi"})
	if out != OutcomeRetry {
		t.Fatalf("out = %v, want retry", out)
	}
}

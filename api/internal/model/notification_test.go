package model

import (
	"strings"
	"testing"
)

func TestRenderDropsUnknownPlaceholders(t *testing.T) {
	got := Render("{{event}} on {{host}} from {{ip}} — {{nope}}",
		map[string]string{"event": "ip.banned", "host": "a.example.com", "ip": "192.0.2.5"})
	want := "ip.banned on a.example.com from 192.0.2.5 — "
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A template written for one event must not break when a different event with
// different fields renders through it.
func TestRenderIsTotal(t *testing.T) {
	if got := Render("{{a}}{{b}}{{c}}", nil); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := Render("no placeholders", map[string]string{"a": "1"}); got != "no placeholders" {
		t.Fatalf("got %q", got)
	}
}

func baseChannelRequest() *CreateNotificationChannelRequest {
	return &CreateNotificationChannelRequest{
		Name:   "ntfy",
		Type:   NotificationTypeWebhook,
		Config: map[string]string{"url": "https://ntfy.example.com/npg"},
		Events: []string{"cert.renewal_failed"},
	}
}

func TestChannelValidate(t *testing.T) {
	t.Run("accepts a public webhook", func(t *testing.T) {
		if err := baseChannelRequest().Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("rejects an unknown type", func(t *testing.T) {
		r := baseChannelRequest()
		r.Type = "carrier-pigeon"
		if err := r.Validate(true); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("rejects an unknown event key", func(t *testing.T) {
		r := baseChannelRequest()
		r.Events = []string{"made.up"}
		if err := r.Validate(true); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("a channel that subscribes to nothing and has no digest is pointless", func(t *testing.T) {
		r := baseChannelRequest()
		r.Events = nil
		if err := r.Validate(true); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("digest alone is enough", func(t *testing.T) {
		r := baseChannelRequest()
		r.Events = nil
		r.DigestEnabled = true
		if err := r.Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("rejects a LAN url without the opt-in", func(t *testing.T) {
		r := baseChannelRequest()
		r.Config["url"] = "https://192.168.1.50/hook"
		if err := r.Validate(true); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("accepts a LAN url with the opt-in", func(t *testing.T) {
		r := baseChannelRequest()
		r.Config["url"] = "https://192.168.1.50/hook"
		r.AllowPrivateTarget = true
		if err := r.Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("telegram needs a token and a chat id", func(t *testing.T) {
		r := baseChannelRequest()
		r.Type = NotificationTypeTelegram
		r.Config = map[string]string{"bot_token": "123:abc"}
		if err := r.Validate(true); err == nil {
			t.Fatal("expected rejection for the missing chat_id")
		}
		r.Config["chat_id"] = "-100123"
		if err := r.Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("telegram does not go through the URL check", func(t *testing.T) {
		// The endpoint is api.telegram.org, not operator-supplied, so there is
		// no url key to validate and its absence must not be an error.
		r := baseChannelRequest()
		r.Type = NotificationTypeTelegram
		r.Config = map[string]string{"bot_token": "123:abc", "chat_id": "-100"}
		if err := r.Validate(true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("digest hour must be a real hour", func(t *testing.T) {
		r := baseChannelRequest()
		r.DigestHour = 25
		if err := r.Validate(true); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("a create needs the secret, an update may keep it", func(t *testing.T) {
		r := baseChannelRequest()
		r.Type = NotificationTypeDiscord
		r.Config = map[string]string{"url": ""}
		if err := r.Validate(true); err == nil {
			t.Fatal("expected a create with no url to be rejected")
		}
		r.Config["url"] = SecretPlaceholder
		if err := r.Validate(false); err != nil {
			t.Fatalf("an update round-tripping the mask should be accepted: %v", err)
		}
	})
}

// Every key the UI offers must exist in the catalogue, and every batched key
// must be marked as such — the dispatcher relies on that flag to decide whether
// a burst is coalesced or sent one by one.
func TestEventCatalogue(t *testing.T) {
	if len(EventCatalogue) == 0 {
		t.Fatal("catalogue is empty")
	}
	seen := map[string]bool{}
	for _, e := range EventCatalogue {
		if seen[e.Key] {
			t.Fatalf("duplicate key %q", e.Key)
		}
		seen[e.Key] = true
		if !strings.Contains(e.Key, ".") {
			t.Errorf("key %q should be namespaced", e.Key)
		}
	}
	for _, want := range []string{"cert.renewal_failed", "ddns.sync_failed", "ip.banned", "backup.failed"} {
		if !seen[want] {
			t.Errorf("catalogue is missing %q", want)
		}
	}
	if !IsBatchedEvent("ip.banned") {
		t.Error("ip.banned must be batched — the peak measured hour is 1,566 blocks")
	}
	if IsBatchedEvent("cert.renewal_failed") {
		t.Error("cert.renewal_failed is edge-triggered, not batched")
	}
}
